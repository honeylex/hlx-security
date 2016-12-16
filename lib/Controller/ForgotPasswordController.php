<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Hlx\Security\View\ForgotPasswordInputView;
use Hlx\Security\View\ForgotPasswordSuccessView;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use ReCaptcha\ReCaptcha;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class ForgotPasswordController
{
    protected $formFactory;

    protected $userService;

    protected $accountService;

    protected $configProvider;

    public function __construct(
        FormFactoryInterface $formFactory,
        UserProviderInterface $userService,
        AccountService $accountService,
        ConfigProviderInterface $configProvider
    ) {
        $this->formFactory = $formFactory;
        $this->userService = $userService;
        $this->accountService = $accountService;
        $this->configProvider = $configProvider;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $request->attributes->set('form', $form);

        return [ ForgotPasswordInputView::CLASS ];
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $form->handleRequest($request);
        $request->attributes->set('form', $form);

        if (!$form->isValid()) {
            return [ ForgotPasswordInputView::CLASS ];
        }

        $formData = $form->getData();
        $username = $formData['username'];

        try {
            $this->validateRecaptcha($request->request->get('g-recaptcha-response'));
            $user = $this->userService->loadUserByUsername($username);
            $this->accountService->startSetUserPassword($user);
        } catch (AuthenticationException $error) {
            $request->attributes->set('form', $this->buildForm($this->formFactory));
            $request->attributes->set('errors', (array) $error->getMessageKey());
            return [ ForgotPasswordInputView::CLASS ];
        }

        return [ ForgotPasswordSuccessView::CLASS ];
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
            ->add('username', TextType::CLASS, [
                'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ],
                'label' => 'Username or Email'
            ])
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
