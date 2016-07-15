<?php

namespace Hlx\Security\Controller;

use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\SetUserPassword\SetUserPasswordCommand;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Shrink0r\Monatic\Success;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\NotBlank;

class PasswordController
{
    protected $formFactory;

    protected $templateRenderer;

    protected $userType;

    protected $userService;

    protected $urlGenerator;

    protected $commandBus;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UserType $userType,
        UserProviderInterface $userService,
        UrlGeneratorInterface $urlGenerator,
        CommandBusInterface $commandBus
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->userType = $userType;
        $this->userService = $userService;
        $this->urlGenerator = $urlGenerator;
        $this->commandBus = $commandBus;
    }

    public function read(Request $request, Application $app)
    {
        $token = $request->get('token');
        // @todo redirect/error on missing/invalid token

        $form = $this->buildForm($this->formFactory, [ 'token' => $token ]);

        return $this->templateRenderer->render(
            '@Security/password.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@Security/password.twig',
                [ 'form' => $form->createView() ]
            );
        }

        $form_data = $form->getData();
        $user = $this->userService->loadUserByToken($form_data['token'], 'verification');
        $result = (new AggregateRootCommandBuilder($this->userType, SetUserPasswordCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withPasswordHash($this->userService->encodePassword($form_data['password']))
            ->build();

        if (!$result instanceof Success) {
            return $this->templateRenderer->render(
                '@Security/password.twig',
                [ 'form' => $form->createView(), 'errors' => $result->get() ]
            );
        }

        $this->commandBus->post($result->get());

        // @todo autologin

        return $app->redirect($this->urlGenerator->generate('hlx.security.login'));
    }

    protected function buildForm(FormFactoryInterface $formFactory, array $data = [])
    {
        return $formFactory->createBuilder(FormType::CLASS, $data)
            ->add('token', HiddenType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('password', RepeatedType::CLASS, [
                'type' => PasswordType::CLASS,
                'constraints' => new NotBlank,
                'invalid_message' => 'The password fields must match.',
                'required' => true,
                'first_options'  => [ 'label' => 'Password' ],
                'second_options' => [ 'label' => 'Repeat Password' ]
            ])
            ->getForm();
    }
}
