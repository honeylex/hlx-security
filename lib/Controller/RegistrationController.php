<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\RegistrationServiceInterface;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class RegistrationController
{
    protected $formFactory;

    protected $templateRenderer;

    protected $urlGenerator;

    protected $registrationService;

    protected $userService;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator,
        RegistrationServiceInterface $registrationService,
        UserProviderInterface $userService
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
        $this->registrationService = $registrationService;
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
        $form = $this->buildRegistrationForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/registration.html.twig',
                [ 'form' => $form->createView() ]
            );
        }

        try {
            $username = $form->getData()['username'];
            $user = $this->userService->loadUserByUsername($username);
        } catch (UsernameNotFoundException $error) {
            $token = StringToolkit::generateRandomToken();
            $this->registrationService->registerUser($form->getData(), $token);
            return $app->redirect($this->urlGenerator->generate('hlx.security.password', [ 'token' => $token ]));
        }

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [
                'form' => $this->buildRegistrationForm($this->formFactory)->createView(),
                'errors' => 'This user is already registered.'
            ]
        );
    }

    public function verify(Request $request, Application $app)
    {
        $token = $request->get('token');
        $user = $this->userService->loadUserByToken($token, 'verification');

        $this->registrationService->verifyUser($user);

        // @todo autologin

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
