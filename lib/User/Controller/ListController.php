<?php

namespace Hlx\Security\User\Controller;

use Honeybee\Infrastructure\DataAccess\Finder\FinderResultInterface;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\DataAccess\Query\SearchCriteria;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\GreaterThan;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class ListController
{
    protected $templateRenderer;

    protected $queryServiceMap;

    protected $urlGenerator;

    protected $validator;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        QueryServiceMap $queryServiceMap,
        UrlGeneratorInterface $urlGenerator,
        ValidatorInterface $validator
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->queryServiceMap = $queryServiceMap;
        $this->urlGenerator = $urlGenerator;
        $this->validator = $validator;
    }

    public function read(Request $request)
    {
        list($query, $page, $limit) = $this->getListParams($request);
        $search = $this->fetchUserList($query, $page, $limit);

        return $this->templateRenderer->render(
            '@hlx-security/user/list.html.twig',
            [
                'q' => '',
                'user_list' => $search,
                'pager' => $this->buildPager($search, $query, $page, $limit)
            ]
        );
    }

    protected function getListParams(Request $request)
    {
        $query = $request->query->get('q', '');
        $errors = $this->validator->validate($query, new Length([ 'max' => 100 ]));
        if (count($errors) > 0) {
            $query = '';
        }

        $page = $request->query->get('page', 1);
        $errors = $this->validator->validate($page, new GreaterThan([ 'value' => 0 ]));
        if (count($errors) > 0) {
            $page = 1;
        }

        $limit = $request->query->get('limit', 10);
        $errors = $this->validator->validate($limit, new GreaterThan([ 'value' => 0 ]));
        if (count($errors) > 0) {
            $limit = 10;
        }

        return [ $query, $page, $limit ];
    }

    protected function fetchUserList($searchTerm, $page, $limit)
    {
        $searchCriteria = new CriteriaList;

        if (!empty($searchTerm)) {
            $searchCriteria->addItem(new SearchCriteria($searchTerm));
        }

        $query = new CriteriaQuery($searchCriteria, new CriteriaList, new CriteriaList, ($page - 1) * $limit, $limit);

        return $this->queryServiceMap
            ->getItem('hlx.security.user::projection.standard::query_service')
            ->find($query);
    }

    protected function buildPager(FinderResultInterface $search, $query, $page, $limit)
    {
        $pager = [
            'total' => ceil($search->getTotalCount() / $limit),
            'current' => $page,
            'next_url' => false,
            'prev_url' => false
        ];

        if (($page + 1) * $limit <= $search->getTotalCount()) {
            $pager['next_url'] = $this->urlGenerator->generate(
                'hlx.security.user.list',
                [ 'page' => $page + 1, 'limit' => $limit, 'q' => $query ]
            );
        }

        if (($page - 1) / $limit > 0) {
            $pager['prev_url'] = $this->urlGenerator->generate(
                'hlx.security.user.list',
                [ 'page' => $page - 1, 'limit' => $limit, 'q' => $query ]
            );
        }

        return $pager;
    }
}
