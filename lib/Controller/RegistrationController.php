<?php

namespace Foh\SystemAccount\Controller;

use DateTime;
use DateInterval;
use Foh\SystemAccount\User\Model\Aggregate\UserType;
use Foh\SystemAccount\User\Model\Task\CreateUser\CreateUserCommand;
use Honeybee\Common\Util\StringToolkit;
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

    public function __construct(
        UserType $userType,
        CommandBusInterface $commandBus,
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildRegistrationForm($this->formFactory);

        return $this->templateRenderer->render(
            '@SystemAccount/registration.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildRegistrationForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@SystemAccount/registration.twig',
                [ 'form' => $form->createView() ]
            );
        }

        // add a default token to the post data
        $token = StringToolkit::generateRandomToken();
        $form_data = $form->getData();
        $form_data['tokens'] = [
            [
                '@type' => 'verification',
                'token' => $token,
                'expires_at' => (new DateTime)->add(new DateInterval('P7D'))
            ]
        ];

        $result = (new AggregateRootCommandBuilder($this->userType, CreateUserCommand::CLASS))
            ->withValues($form_data)
            ->build();

        if (!$result instanceof Success) {
            return $this->templateRenderer->render(
                '@SystemAccount/registration.twig',
                [ 'form' => $form->createView(), 'errors' => $result->get() ]
            );
        }

        $this->commandBus->post($result->get());

        return $app->redirect($this->urlGenerator->generate('foh.system_account.password', [ 'token' => $token ]));
    }

    protected function buildRegistrationForm(FormFactoryInterface $formFactory)
    {
        return $this->formFactory->createBuilder(FormType::CLASS)
            ->add('username', TextType::CLASS, ['constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ]])
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
