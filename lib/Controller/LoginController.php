<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Hlx\Security\View\LoginInputView;
use Hlx\Security\View\LoginSuccessView;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class LoginController
{
    protected $formFactory;

    protected $userService;

    protected $accountService;

    public function __construct(
        FormFactoryInterface $formFactory,
        UserProviderInterface $userService,
        AccountService $accountService
    ) {
        $this->formFactory = $formFactory;
        $this->userService = $userService;
        $this->accountService = $accountService;
    }

    public function read(Request $request, Application $app)
    {
        $lastUsername = $request->getSession()->get(Security::LAST_USERNAME);
        $form = $this->buildForm($lastUsername);
        $request->attributes->set('form', $form);

        return [ LoginInputView::CLASS ];
    }

    /*
     * Controller for API token login only
     */
    public function write(Request $request, Application $app)
    {
        $username = $request->request->get('username');
        $password = $request->request->get('password');

        $user = $this->userService->loadUserByUsername($username);
        if (!$this->userService->isPasswordValid($user->getPassword(), $password, $user->getSalt())) {
            throw new BadCredentialsException;
        }

        $this->accountService->loginUser($user);
        $request->attributes->set('user', $user);

        return [ LoginSuccessView::CLASS ];
    }

    protected function buildForm($lastUsername)
    {
        return $this->formFactory->createNamedBuilder(
            null,
            FormType::CLASS,
            [ 'username' => $lastUsername ],
            [ 'translation_domain' => 'form' ]
        )
            ->add('username', EmailType::CLASS, [
                // constrain to email because of potential Oauth related username duplication
                'constraints' => new NotBlank,
                'label' => 'Email Address'
            ])
            ->add('password', PasswordType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('remember_me', CheckboxType::CLASS, [ 'data' => true, 'required' => false ])
            ->getForm();
    }
}
