<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountServiceInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\NotBlank;

class ForgotPasswordController
{
    protected $formFactory;

    protected $templateRenderer;

    protected $userService;

    protected $accountService;

    protected $urlGenerator;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UserProviderInterface $userService,
        AccountServiceInterface $accountService,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->userService = $userService;
        $this->accountService = $accountService;
        $this->urlGenerator = $urlGenerator;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);

        return $this->templateRenderer->render(
            '@hlx-security/forgot_password.html.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/forgot_password.html.twig',
                [ 'form' => $form->createView() ]
            );
        }

        $formData = $form->getData();
        $email = $formData['email'];

        try {
            $user = $this->userService->loadUserByEmail($email);
            $this->accountService->startSetUserPassword($user);
        } catch (AuthenticationException $error) {
            return $this->templateRenderer->render(
                '@hlx-security/forgot_password.html.twig',
                [
                    'form' => $this->buildForm($this->formFactory)->createView(),
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
}
