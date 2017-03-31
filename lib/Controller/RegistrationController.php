<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Hlx\Security\View\RegistrationInputView;
use Hlx\Security\View\RegistrationSuccessView;
use Honeylex\Config\ConfigProviderInterface;
use ReCaptcha\ReCaptcha;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class RegistrationController
{
    protected $formFactory;

    protected $accountService;

    protected $userProvider;

    protected $tokenStorage;

    protected $configProvider;

    public function __construct(
        FormFactoryInterface $formFactory,
        AccountService $accountService,
        UserProviderInterface $userProvider,
        TokenStorageInterface $tokenStorage,
        ConfigProviderInterface $configProvider
    ) {
        $this->formFactory = $formFactory;
        $this->accountService = $accountService;
        $this->userProvider = $userProvider;
        $this->tokenStorage = $tokenStorage;
        $this->configProvider = $configProvider;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $request->attributes->set('form', $form);

        return [ RegistrationInputView::CLASS ];
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $form->handleRequest($request);
        $request->attributes->set('form', $form);

        if (!$form->isValid()) {
            return [ RegistrationInputView::CLASS ];
        }

        $formData = $form->getData();
        $username = $formData['username'];
        $email = $formData['email'];

        try {
            $this->validateRecaptcha($request->request->get('g-recaptcha-response'));
            if (!$this->userProvider->userExists($username, $email)) {
                $this->accountService->registerUser($formData);
                // auto login handling - expects registration to be synchronous
                if ($this->configProvider->getSetting('hlx.security.auto_login.enabled') && $request->hasSession()) {
                    $firewall = $this->configProvider->getSetting('hlx.security.auto_login.firewall', 'default');
                    $user = $this->userProvider->loadUserByEmail($email);
                    $token = new UsernamePasswordToken($user, null, $firewall, $user->getRoles());
                    $this->tokenStorage->setToken($token);
                    $request->getSession()->set('_security_'.$firewall, serialize($token));
                }
                return [ RegistrationSuccessView::CLASS ];
            }
        } catch (AuthenticationException $error) {
            $errors = (array)$error->getMessageKey();
        }

        $request->attributes->set('errors', isset($errors) ? $errors : [ 'User is already registered.' ]);
        return [ RegistrationInputView::CLASS ];
    }

    public function verify(Request $request, Application $app)
    {
        $token = $request->get('token');

        $user = $this->userProvider->loadUserByToken($token, 'verification');

        $this->accountService->verifyUser($user);

        return [ RegistrationSuccessView::CLASS ];
    }

    protected function buildForm()
    {
        return $this->formFactory->createNamedBuilder(
            null,
            FormType::CLASS,
            [],
            // @todo remove allow_extra_fields when recaptcha can be created via form builder
            [ 'translation_domain' => 'form', 'allow_extra_fields' => true ]
        )
            ->add('username', TextType::CLASS, [ 'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ] ])
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('password', RepeatedType::CLASS, [
                'type' => PasswordType::CLASS,
                'constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ],
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
