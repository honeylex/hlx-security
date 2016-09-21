<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\User\View\ListSuccessView;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\DataAccess\Query\SearchCriteria;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\GreaterThan;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class ListController
{
    protected $queryServiceMap;

    protected $validator;

    public function __construct(QueryServiceMap $queryServiceMap, ValidatorInterface $validator)
    {
        $this->queryServiceMap = $queryServiceMap;
        $this->validator = $validator;
    }

    public function read(Request $request, Application $app)
    {
        list($query, $page, $limit) = $this->getListParams($request);
        $search = $this->fetchUserList($query, $page, $limit);

        $request->attributes->set('query', $query);
        $request->attributes->set('page', $page);
        $request->attributes->set('limit', $limit);
        $request->attributes->set('search', $search);

        return [ ListSuccessView::CLASS ];
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

        $query = new CriteriaQuery(
            $searchCriteria,
            new CriteriaList,
            new CriteriaList,
            ($page - 1) * $limit,
            $limit
        );

        return $this->queryServiceMap
            ->getItem('hlx.security.user::projection.standard::query_service')
            ->find($query);
    }
}
