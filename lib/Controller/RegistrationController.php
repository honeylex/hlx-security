<?php

namespace Hlx\Security\Controller;

use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\ProceedUserWorkflow\ProceedUserWorkflowCommand;
use Hlx\Security\User\Model\Task\RegisterUser\RegisterUserCommand;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
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
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class RegistrationController
{
    protected $userType;

    protected $commandBus;

    protected $formFactory;

    protected $templateRenderer;

    protected $urlGenerator;

    protected $configProvider;

    protected $userService;

    public function __construct(
        UserType $userType,
        CommandBusInterface $commandBus,
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator,
        ConfigProviderInterface $configProvider,
        UserProviderInterface $userService
    ) {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
        $this->configProvider = $configProvider;
        $this->userService = $userService;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildRegistrationForm($this->formFactory);

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        // validate the from data
        $form = $this->buildRegistrationForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/registration.html.twig',
                [ 'form' => $form->createView() ]
            );
        }

        // build and check command
        $token = StringToolkit::generateRandomToken();
        $result = (new AggregateRootCommandBuilder($this->userType, RegisterUserCommand::CLASS))
            ->withValues($form->getData())
            ->withVerificationToken($token)
            ->build();

        if (!$result instanceof Success) {
            return $this->templateRenderer->render(
                '@hlx-security/registration.html.twig',
                [ 'form' => $form->createView(), 'errors' => $result->get() ]
            );
        }

        $this->commandBus->post($result->get());

        return $app->redirect($this->urlGenerator->generate('hlx.security.password', [ 'token' => $token ]));
    }

    public function verify(Request $request, Application $app)
    {
        $token = $request->get('token');
        $user = $this->userService->loadUserByToken($token, 'verification');

        if ($user->getWorkflowState() === 'unverified') {
            $result = (new AggregateRootCommandBuilder($this->userType, ProceedUserWorkflowCommand::CLASS))
                ->withAggregateRootIdentifier($user->getIdentifier())
                ->withKnownRevision($user->getRevision())
                ->withCurrentStateName('unverified')
                ->withEventName('promote')
                ->build();

            if (!$result instanceof Success) {
                return $this->templateRenderer->render(
                    '@hlx-security/login.html.twig',
                    [ 'form' => $form->createView(), 'errors' => $result->get() ]
                );
            }

            $this->commandBus->post($result->get());

            // @todo autologin
        }

        return $app->redirect($this->urlGenerator->generate('hlx.security.login'));
    }

    protected function buildRegistrationForm(FormFactoryInterface $formFactory)
    {
        return $this->formFactory->createBuilder(FormType::CLASS)
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
}
