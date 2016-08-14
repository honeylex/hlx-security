<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\LogoutException;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class LoginController implements LogoutSuccessHandlerInterface
{
    protected $formFactory;

    protected $templateRenderer;

    protected $tokenStorage;

    protected $httpUtils;

    protected $accountService;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        TokenStorageInterface $tokenStorage,
        HttpUtils $httpUtils,
        AccountService $accountService
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->tokenStorage = $tokenStorage;
        $this->httpUtils = $httpUtils;
        $this->accountService = $accountService;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildLoginForm($this->formFactory);

        $error = $app['security.last_error']($request);
        $lastUsername = $request->getSession()->get('_security.last_username');

        return $this->templateRenderer->render(
            '@hlx-security/login.html.twig',
            [
                'form' => $form->createView(),
                'last_username' => $lastUsername,
                'errors' => (array) $error
            ]
        );
    }

    public function onLogoutSuccess(Request $request)
    {
        $token = $this->tokenStorage->getToken();

        // Reset authentication token for the user on logout
        if ($token instanceof TokenInterface) {
            $user = $token->getUser();
            $this->accountService->logoutUser($user);
        }

        return $this->httpUtils->createRedirectResponse($request, '/');
    }

    protected function buildLoginForm(FormFactoryInterface $formFactory)
    {
        return $formFactory->createNamedBuilder(null, FormType::CLASS)
            ->add('_username', TextType::CLASS, [
                'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ],
                'label' => 'Username or Email'
            ])
            ->add('_password', PasswordType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('_remember_me', CheckboxType::CLASS, [ 'data' => true ])
            ->getForm();
    }
}
