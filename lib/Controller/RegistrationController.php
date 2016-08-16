<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use ReCaptcha\ReCaptcha;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
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

    protected $accountService;

    protected $userService;

    protected $tokenStorage;

    protected $recaptchaSettings;

    protected $autoLoginSettings;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator,
        AccountService $accountService,
        UserProviderInterface $userService,
        ConfigProviderInterface $configProvider,
        TokenStorageInterface $tokenStorage
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
        $this->accountService = $accountService;
        $this->userService = $userService;
        $this->tokenStorage = $tokenStorage;
        $crateSettings = $configProvider->getCrateMap()->getItem('hlx.security')->getSettings();
        $this->recaptchaSettings = $crateSettings->get('recaptcha', new Settings);
        $this->autoLoginSettings = $crateSettings->get('auto_login', new Settings);
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildRegistrationForm($this->formFactory);

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [
                'form' => $form->createView(),
                'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                'recaptcha_site_key' => $this->recaptchaSettings->get('site_key')
            ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildRegistrationForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/registration.html.twig',
                [
                    'form' => $form->createView(),
                    'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                    'recaptcha_site_key' => $this->recaptchaSettings->get('site_key')
                ]
            );
        }

        $formData = $form->getData();
        $username = $formData['username'];
        $email = $formData['email'];

        try {
            $this->validateRecaptcha($request->request->get('g-recaptcha-response'));
            if (!$this->userService->userExists($username, $email)) {
                $this->accountService->registerUser($formData);
                // auto login handling - requires sync registration
                if ($this->autoLoginSettings->get('enabled') && $session = $request->getSession()) {
                    $firewall = $this->autoLoginSettings->get('firewall', 'default');
                    $user = $this->userService->loadUserByEmail($email);
                    $token = new UsernamePasswordToken($user, null, $firewall, $user->getRoles());
                    $this->tokenStorage->setToken($token);
                    $session->set('_security_'.$firewall, serialize($token));
                    $session->save();
                    $targetPath = $this->autoLoginSettings->get('target_path', 'home');
                    return $app->redirect($this->urlGenerator->generate($targetPath));
                } else {
                    return $app->redirect($this->urlGenerator->generate('hlx.security.login'));
                }
            }
        } catch (AuthenticationException $error) {
            $errors = (array) $error->getMessageKey();
        }

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [
                'form' => $form->createView(),
                'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                'recaptcha_site_key' => $this->recaptchaSettings->get('site_key'),
                'errors' => isset($errors) ? $errors : [ 'This user is already registered.' ]
            ]
        );
    }

    public function verify(Request $request, Application $app)
    {
        $token = $request->get('token');

        $user = $this->userService->loadUserByToken($token, 'verification');

        $this->accountService->verifyUser($user);

        return $app->redirect($this->urlGenerator->generate('hlx.security.login'));
    }

    protected function buildRegistrationForm(FormFactoryInterface $formFactory)
    {
        return $this->formFactory->createBuilder(FormType::CLASS)
            ->add('username', TextType::CLASS, [ 'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ] ])
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('password', RepeatedType::CLASS, [
                'type' => PasswordType::CLASS,
                'constraints' => new NotBlank,
                'invalid_message' => 'The password fields must match.',
                'required' => true,
                'first_options'  => [ 'label' => 'Password' ],
                'second_options' => [ 'label' => 'Repeat Password' ]
            ])
            ->add('firstname', TextType::CLASS, [ 'required' => false ])
            ->add('lastname', TextType::CLASS, [ 'required' => false ])
            ->add('role', ChoiceType::CLASS, [
                'choices' => [ 'Administrator' => 'administrator', 'User' => 'user' ],
                'constraints' => new Choice([ 'administrator', 'user' ]),
            ])
            ->getForm();
    }

    protected function validateRecaptcha($gRecaptchaResponse, $remoteIp = null)
    {
        if ($this->recaptchaSettings->get('enabled')) {
            $recaptcha = new ReCaptcha($this->recaptchaSettings->get('secret_key'));
            $response = $recaptcha->verify($gRecaptchaResponse, $remoteIp);
            if (!$response->isSuccess()) {
                $errors = $response->getErrorCodes();
                throw new CustomUserMessageAuthenticationException('Recaptcha failure.');
            }
        }
    }
}
