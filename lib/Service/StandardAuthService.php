<?php

namespace Foh\SystemAccount\Service;

use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\DataAccess\Query\AttributeCriteria;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\Query;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\DataAccess\Query\Comparison\Equals;
use Honeybee\Infrastructure\Security\Auth\AuthResponse;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Honeybee\Infrastructure\Security\Auth\CryptedPasswordHandler;

class StandardAuthService implements AuthServiceInterface
{
    const ACTIVE_STATE = 'active';

    const TYPE_KEY = 'standard-auth';

    protected $config;

    protected $password_handler;

    protected $query_service_map;

    public function __construct(
        ConfigInterface $config,
        QueryServiceMap $query_service_map,
        CryptedPasswordHandler $password_handler
    ) {
        $this->config = $config;
        $this->query_service_map = $query_service_map;
        $this->password_handler = $password_handler;
    }

    public function getTypeKey()
    {
        return static::TYPE_KEY;
    }

    public function findByUsername($username)
    {
        $query_result = $this->getQueryService()->find(
            new Query(
                new CriteriaList,
                new CriteriaList([ new AttributeCriteria('username', new Equals($username)) ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $query_result->getTotalCount()) {
            $user = $query_result->getFirstResult();
        }

        return $user;
    }

    // @todo nested query
    public function findByToken($token, $type)
    {
        $query_result = $this->getQueryService()->find(
            new Query(
                new CriteriaList,
                new CriteriaList([
                    new AttributeCriteria('tokens.token', new Equals($token)),
                ]),
                new CriteriaList,
                0,
                1
            )
        );

        $user = null;
        if (1 === $query_result->getTotalCount()) {
            $user = $query_result->getFirstResult();
        }

        return $user;
    }

    /**
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     * @codingStandardsIgnoreStart
     */
    public function authenticate($username, $password, $options = []) // @codingStandardsIgnoreEnd
    {
        $user = $this->findByUsername($username);

        if (!$user) {
            return new AuthResponse(AuthResponse::STATE_UNAUTHORIZED, 'authentication failed');
        }
        /*if ($user->getWorkflowState() !== $this->config->get('active_state', self::ACTIVE_STATE)) {
            return new AuthResponse(
                AuthResponse::STATE_UNAUTHORIZED,
                "user inactive"
            );
        }*/

        if ($this->password_handler->verify($password, $user->getPasswordHash())) {
            return new AuthResponse(
                AuthResponse::STATE_AUTHORIZED,
                'authenticaton success',
                [
                    'login' => $user->getUsername(),
                    'email' => $user->getEmail(),
                    'acl_role' => $user->getRole(),
                    'name' => $user->getFirstname() . ' ' . $user->getLastname(),
                    'identifier' => $user->getIdentifier(),
                    'background_images' => $user->getBackgroundImages()
                ]
            );
        }

        return new AuthResponse(AuthResponse::STATE_UNAUTHORIZED, 'authentication failed');
    }

    public function encodePassword($password)
    {
        return $this->password_handler->hash($password);
    }

    protected function getQueryService()
    {
        $query_service_key = $this->config->get('query_service', 'foh.system_account.user::query_service');
        return $this->query_service_map->getItem($query_service_key);
    }
}
