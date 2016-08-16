<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\NotBlank;

class SetPasswordController
{
    protected $formFactory;

    protected $templateRenderer;

    protected $userService;

    protected $urlGenerator;

    protected $accountService;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        UserProviderInterface $userService,
        UrlGeneratorInterface $urlGenerator,
        AccountService $accountService
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->userService = $userService;
        $this->urlGenerator = $urlGenerator;
        $this->accountService = $accountService;
    }

    public function read(Request $request, Application $app)
    {
        $token = $request->get('token');

        $form = $this->buildForm($this->formFactory, [ 'token' => $token ]);

        return $this->templateRenderer->render(
            '@hlx-security/set_password.html.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm($this->formFactory);
        $form->handleRequest($request);

        if (!$form->isValid()) {
            return $this->templateRenderer->render(
                '@hlx-security/set_password.html.twig',
                [ 'form' => $form->createView() ]
            );
        }

        $formData = $form->getData();
        $token = $formData['token'];
        $password = $formData['password'];

        try {
            $user = $this->userService->loadUserByToken($formData['token'], 'set_password');
            $this->accountService->setUserPassword($user, $password);
            // We can verify the user at this point if required
            $this->accountService->verifyUser($user);
        } catch (AuthenticationException $error) {
            return $this->templateRenderer->render(
                '@hlx-security/set_password.html.twig',
                [
                    'form' => $this->buildForm($this->formFactory, [ 'token' => $token ])->createView(),
                    'errors' => (array) $error->getMessageKey()
                ]
            );
        }

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
