<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use ReCaptcha\ReCaptcha;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\NotBlank;

class ForgotPasswordController
{
    protected $formFactory;

    protected $templateRenderer;

    protected $userService;

    protected $accountService;

    protected $urlGenerator;

    protected $recaptchaSettings;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UserProviderInterface $userService,
        AccountService $accountService,
        UrlGeneratorInterface $urlGenerator,
        ConfigProviderInterface $configProvider
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->userService = $userService;
        $this->accountService = $accountService;
        $this->urlGenerator = $urlGenerator;
        $crateSettings = $configProvider->getCrateMap()->getItem('hlx.security')->getSettings();
        $this->recaptchaSettings = $crateSettings->get('recaptcha', new Settings);
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);

        return $this->templateRenderer->render(
            '@hlx-security/forgot_password.html.twig',
            [
                'form' => $form->createView(),
                'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                'recaptcha_site_key' => $this->recaptchaSettings->get('site_key')
            ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/forgot_password.html.twig',
                [
                    'form' => $form->createView(),
                    'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                    'recaptcha_site_key' => $this->recaptchaSettings->get('site_key')
                ]
            );
        }

        $formData = $form->getData();
        $email = $formData['email'];

        try {
            $this->validateRecaptcha($request->request->get('g-recaptcha-response'));
            $user = $this->userService->loadUserByEmail($email);
            $this->accountService->startSetUserPassword($user);
        } catch (AuthenticationException $error) {
            return $this->templateRenderer->render(
                '@hlx-security/forgot_password.html.twig',
                [
                    'form' => $this->buildForm($this->formFactory)->createView(),
                    'recaptcha_enabled' => $this->recaptchaSettings->get('enabled'),
                    'recaptcha_site_key' => $this->recaptchaSettings->get('site_key'),
                    'errors' => (array) $error->getMessageKey()
                ]
            );
        }

        return $app->redirect($this->urlGenerator->generate('hlx.security.login'));
    }

    protected function buildForm(FormFactoryInterface $formFactory, array $data = [])
    {
        return $formFactory->createBuilder(FormType::CLASS, $data)
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->getForm();
    }

    protected function validateRecaptcha($gRecaptchaResponse, $remoteIp = null)
    {
        if ($this->recaptchaSettings->get('enabled')) {
            $recaptcha = new ReCaptcha($this->recaptchaSettings->get('secret_key'));
            $response = $recaptcha->verify($gRecaptchaResponse, $remoteIp);
            if (!$response->isSuccess()) {
                $errors = $response->getErrorCodes();
                throw new CustomUserMessageAuthenticationException('Recaptcha failed.');
            }
        }
    }
}
