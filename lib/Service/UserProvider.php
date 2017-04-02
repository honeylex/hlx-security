<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Hlx\Security\User\OauthUser;
use Hlx\Security\User\User;
use Honeybee\Infrastructure\DataAccess\Finder\FinderMap;
use Honeybee\Infrastructure\DataAccess\Query\AttributeCriteria;
use Honeybee\Infrastructure\DataAccess\Query\Comparison\Equals;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface, OAuthUserProviderInterface
{
    protected $queryServiceMap;

    protected $finderMap;

    protected $userManager;

    public function __construct(
        QueryServiceMap $queryServiceMap,
        FinderMap $finderMap,
        UserManager $userManager,
        TokenStorageInterface $tokenStorage
    ) {
        $this->queryServiceMap = $queryServiceMap;
        $this->finderMap = $finderMap;
        $this->userManager = $userManager;
        $this->tokenStorage = $tokenStorage;
    }

    public function loadUserByIdentifier($identifier)
    {
        $result = $this->getFinder()->getByIdentifier($identifier);

        if (1 === $result->getTotalCount()) {
            $securityUser = $result->getFirstResult();
        } else {
            throw new UsernameNotFoundException;
        }

        return new User($securityUser->toArray());
    }

    public function loadUserByUsername($username)
    {
        $result = $this->getQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                new CriteriaList(
                    [
                        new AttributeCriteria('username', new Equals($username)),
                        new AttributeCriteria('email', new Equals($username))
                    ],
                    CriteriaList::OP_OR
                ),
                new CriteriaList,
                0,
                1
            )
        );

        if (1 === $result->getTotalCount()) {
            $securityUser = $result->getFirstResult();
        } else {
            throw new UsernameNotFoundException;
        }

        return new User($securityUser->toArray());
    }

    public function loadUserByToken($token, $type)
    {
        // @note could match multiple users since type filter is not applied
        $result = $this->getQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                new CriteriaList([
                    new AttributeCriteria('tokens.token', new Equals($token)),
                ]),
                new CriteriaList,
                0,
                1
            )
        );

        if (1 === $result->getTotalCount()) {
            $securityUser = $result->getFirstResult();
        } else {
            throw new UsernameNotFoundException;
        }

        return new User($securityUser->toArray());
    }

    public function loadUserByEmail($email)
    {
        $result = $this->getQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                new CriteriaList([ new AttributeCriteria('email', new Equals($email)) ]),
                new CriteriaList,
                0,
                1
            )
        );

        if (1 === $result->getTotalCount()) {
            $securityUser = $result->getFirstResult();
        } else {
            throw new UsernameNotFoundException;
        }

        return new User($securityUser->toArray());
    }

    public function loadUserByOAuthCredentials(OAuthTokenInterface $token)
    {
        $email = $token->getEmail();

        try {
            $user = $this->loadUserByEmail($email);
            $this->userManager->handleOauthUser($user, $token);
        } catch (UsernameNotFoundException $error) {
            $this->userManager->registerOauthUser($token);
        }

        // load again to get updated token and proceed workflow
        $user = $this->loadUserByEmail($email);
        $this->userManager->verifyUser($user);

        // @note may need to refresh workflow state although refreshUser is
        // typically called by framework on next page load anyway

        return new OauthUser($user->toArray(), $token->getService());
    }

    public function userExists($username, $email, array $ignoreIds = [])
    {
        $filterCriteriaList = new CriteriaList([
            new CriteriaList(
                [
                    new AttributeCriteria('username', new Equals($username)),
                    new AttributeCriteria('email', new Equals($email))
                ],
                CriteriaList::OP_OR
            )
        ]);

        if (!empty($ignoreIds)) {
            $filterCriteriaList->addItem(new AttributeCriteria('_id', new Equals($ignoreIds, true)));
        }

        $result = $this->getQueryService()->find(
            new CriteriaQuery(
                new CriteriaList,
                $filterCriteriaList,
                new CriteriaList,
                0,
                1000
            )
        );

        return $result->getTotalCount() > 0;
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException;
        }

        $refreshedUser = $this->loadUserByIdentifier($user->getIdentifier());

        return $user->createCopyWith($refreshedUser->toArray());
    }

    public function supportsClass($class)
    {
        return User::CLASS === $class || is_subclass_of($class, User::CLASS);
    }

    protected function getFinder()
    {
        return $this->finderMap->getItem('hlx.security.user::projection.standard::view_store::finder');
    }

    protected function getQueryService()
    {
        return $this->queryServiceMap->getItem('hlx.security.user::projection.standard::view_store::query_service');
    }
}
