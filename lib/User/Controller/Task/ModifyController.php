<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\ModifyUser\ModifyUserCommand;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Infrastructure\DataAccess\Finder\FinderMap;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Shrink0r\Monatic\Success;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class ModifyController
{
    protected $userType;

    protected $templateRenderer;

    protected $commandBus;

    protected $queryServiceMap;

    protected $formFactory;

    protected $urlGenerator;

    public function __construct(
        UserType $userType,
        TemplateRendererInterface $templateRenderer,
        CommandBusInterface $commandBus,
        FinderMap $finderMap,
        FormFactoryInterface $formFactory,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->userType = $userType;
        $this->templateRenderer = $templateRenderer;
        $this->commandBus = $commandBus;
        $this->finderMap = $finderMap;
        $this->formFactory = $formFactory;
        $this->urlGenerator = $urlGenerator;
    }

    public function read(Request $request)
    {
        $user = $this->fetchUser($request->get('identifier'));
        $form = $this->buildUserForm($user->toArray());

        return $this->templateRenderer->render(
            '@Security/user/task/modify.twig',
            [ 'form' => $form->createView(), 'user' => $user ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $user = $this->fetchUser($request->get('identifier'));
        $form = $this->buildUserForm($user->toArray());
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@Security/user/task/modify.twig',
                [ 'form' => $form->createView(), 'user' => $user ]
            );
        }

        $result = (new AggregateRootCommandBuilder($this->userType, ModifyUserCommand::CLASS))
            ->fromEntity($user)
            ->withValues($form->getData())
            ->build();

        if (!$result instanceof Success) {
            return $this->templateRenderer->render(
                '@Security/user/task/modify.twig',
                [ 'form' => $form->createView(), 'user' => $user, 'errors' => $result->get() ]
            );
        }

        $this->commandBus->post($result->get());

        return $app->redirect($this->urlGenerator->generate('hlx.security.user.list'));
    }

    protected function fetchUser($identifier)
    {
        $finder = $this->finderMap->getItem($this->userType->getPrefix().'::projection.standard::view_store::finder');
        $results = $finder->getByIdentifier($identifier);
        return $results->getFirstResult();
    }

    protected function buildUserForm(array $data = [])
    {
        $data = $data ?: [
            'username' => '',
            'firstname' => '',
            'lastname' => '',
            'email' => '',
            'role' => ''
        ];

        return $this->formFactory->createBuilder(FormType::CLASS, $data)
            ->add('username', TextType::CLASS, [ 'constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ]])
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('firstname', TextType::CLASS, [ 'required' => false ])
            ->add('lastname', TextType::CLASS, [ 'required' => false ])
            ->add('role', ChoiceType::CLASS, [
                'choices' => [ 'administrator' => 'administrator', 'user' => 'user' ],
                'constraints' => new Choice([ 'administrator', 'user' ]),
            ])
            ->getForm();
    }
}
