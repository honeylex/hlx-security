<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\Infrastructure\DataAccess\Finder\FinderResultInterface;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaList;
use Honeybee\Infrastructure\DataAccess\Query\CriteriaQuery;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\DataAccess\Query\SearchCriteria;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Form;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\GreaterThan;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class ListController
{
    protected $templateRenderer;

    protected $queryServiceMap;

    protected $urlGenerator;

    protected $formFactory;

    protected $validator;

    protected $userService;

    protected $accountService;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        QueryServiceMap $queryServiceMap,
        UrlGeneratorInterface $urlGenerator,
        FormFactoryInterface $formFactory,
        ValidatorInterface $validator,
        UserProviderInterface $userService,
        AccountService $accountService
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->queryServiceMap = $queryServiceMap;
        $this->urlGenerator = $urlGenerator;
        $this->formFactory = $formFactory;
        $this->validator = $validator;
        $this->userService = $userService;
        $this->accountService = $accountService;
    }

    public function read(Request $request)
    {
        return $this->renderTemplate($request, $this->buildUserForm());
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildUserForm();
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->renderTemplate($request, $form);
        }

        $formData = $form->getData();
        $username = $formData['username'];
        $email = $formData['email'];

        try {
            // check username or email do not exist
            $this->userService->loadUserByUsernameOrEmail($username, $email);
        } catch (UsernameNotFoundException $error) {
            $token = StringToolkit::generateRandomToken();
            $this->accountService->registerUser($formData, $token);
            return $app->redirect($request->getRequestUri());
        }

        return $this->renderTemplate($request, $form, [ 'This user is already registered.' ]);
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

    protected function buildUserForm()
    {
        $data = [
            'username' => '',
            'firstname' => '',
            'lastname' => '',
            'email' => '',
            'role' => ''
        ];

        return $this->formFactory->createBuilder(FormType::CLASS, $data)
            ->add('username', TextType::CLASS, ['constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ]])
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('firstname', TextType::CLASS, [ 'required' => false ])
            ->add('lastname', TextType::CLASS, [ 'required' => false ])
            ->add('role', ChoiceType::CLASS, [
                'choices' => [ 'Administrator' => 'administrator', 'User' => 'user' ],
                'constraints' => new Choice([ 'administrator', 'user' ]),
            ])
            ->getForm();
    }

    protected function renderTemplate(Request $request, Form $form, array $errors = [])
    {
        list($query, $page, $limit) = $this->getListParams($request);
        $search = $this->fetchUserList($query, $page, $limit);

        return $this->templateRenderer->render(
            '@hlx-security/user/list.html.twig',
            [
                'q' => '',
                'user_list' => $search,
                'form' => $form->createView(),
                'pager' => $this->buildPager($search, $query, $page, $limit),
                'errors' => $errors
            ]
        );
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
