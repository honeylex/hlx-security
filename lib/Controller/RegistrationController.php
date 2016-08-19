<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use ReCaptcha\ReCaptcha;
use Silex\Application;
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

    protected $configProvider;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator,
        AccountService $accountService,
        UserProviderInterface $userService,
        TokenStorageInterface $tokenStorage,
        ConfigProviderInterface $configProvider
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
        $this->accountService = $accountService;
        $this->userService = $userService;
        $this->tokenStorage = $tokenStorage;
        $this->configProvider = $configProvider;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm();

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/registration.html.twig',
                [ 'form' => $form->createView() ]
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
                if ($this->configProvider->getSetting('hlx.security.auto_login.enabled')
                    && $session = $request->getSession()
                ) {
                    $firewall = $this->configProvider->getSetting('hlx.security.auto_login.firewall', 'default');
                    $user = $this->userService->loadUserByEmail($email);
                    $token = new UsernamePasswordToken($user, null, $firewall, $user->getRoles());
                    $this->tokenStorage->setToken($token);
                    $session->set('_security_'.$firewall, serialize($token));
                    $targetPath = $this->configProvider->getSetting('hlx.security.auto_login.target_path', 'home');
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

    protected function buildForm()
    {
        return $this->formFactory->createBuilder(FormType::CLASS, [], [ 'translation_domain' => 'form' ])
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
            ->getForm();
    }

    protected function validateRecaptcha($gRecaptchaResponse, $remoteIp = null)
    {
        if ($this->configProvider->getSetting('hlx.security.recaptcha.enabled')) {
            $recaptcha = new ReCaptcha($this->configProvider->getSetting('hlx.security.recaptcha.secret_key'));
            $response = $recaptcha->verify($gRecaptchaResponse, $remoteIp);
            if (!$response->isSuccess()) {
                $errors = $response->getErrorCodes();
                throw new CustomUserMessageAuthenticationException('Recaptcha failed.');
            }
        }
    }
}
