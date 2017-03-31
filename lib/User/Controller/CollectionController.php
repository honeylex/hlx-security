<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\User\View\CollectionSuccessView;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\DataAccess\Query\SearchCriteria;
use Pagerfanta\Adapter\FixedAdapter;
use Pagerfanta\Pagerfanta;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Constraints\GreaterThan;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class CollectionController
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
        $query = $request->query->get('q', '');
        $page = (int) $request->query->get('page', 1);
        $limit = (int) $request->query->get('limit', 10);

        $users = $this->loadUsers($query, $page, $limit);
        $request->attributes->set('users', $users);

        return [ CollectionSuccessView::CLASS ];
    }

    protected function loadUsers($search, $page, $limit)
    {
        $errors = $this->validator->validate($search, new Length([ 'max' => 100 ]));
        if (count($errors) > 0) {
            $search = '';
        }

        $errors = $this->validator->validate($page, new GreaterThan([ 'value' => 0 ]));
        if (count($errors) > 0) {
            $page = 1;
        }

        $errors = $this->validator->validate($limit, new GreaterThan([ 'value' => 0 ]));
        if (count($errors) > 0) {
            $limit = 10;
        }

        $searchCriteria = new CriteriaList;
        if (!empty($search)) {
            $searchCriteria->addItem(new SearchCriteria($search));
        }

        $query = new CriteriaQuery(
            $searchCriteria,
            new CriteriaList,
            new CriteriaList,
            ($page - 1) * $limit,
            $limit
        );

        $finderResult = $this->queryServiceMap
            ->getItem('hlx.security.user::projection.standard::view_store::query_service')
            ->find($query);

        return (new Pagerfanta(new FixedAdapter($finderResult->getTotalCount(), $finderResult->getResults())))
            ->setMaxPerPage($limit) // call before setCurrentPage()
            ->setCurrentPage($page);
    }
}
