<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Hlx\Security\View\SetPasswordInputView;
use Hlx\Security\View\SetPasswordSuccessView;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class SetPasswordController
{
    protected $formFactory;

    protected $userProvider;

    protected $accountService;

    public function __construct(
        FormFactoryInterface $formFactory,
        UserProviderInterface $userProvider,
        AccountService $accountService
    ) {
        $this->formFactory = $formFactory;
        $this->userProvider = $userProvider;
        $this->accountService = $accountService;
    }

    public function read(Request $request, Application $app)
    {
        $token = $request->get('token');
        $form = $this->buildForm([ 'token' => $token ]);
        $request->attributes->set('form', $form);

        return [ SetPasswordInputView::CLASS ];
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $form->handleRequest($request);
        $request->attributes->set('form', $form);

        if (!$form->isValid()) {
            return [ SetPasswordInputView::CLASS ];
        }

        $formData = $form->getData();
        $token = $formData['token'];
        $password = $formData['password'];

        try {
            $user = $this->userProvider->loadUserByToken($formData['token'], 'set_password');
            $this->accountService->setUserPassword($user, $password);
            // We can verify the user at this point if required
            $this->accountService->verifyUser($user);
        } catch (AuthenticationException $error) {
            $request->attributes->set('form', $this->buildForm($this->formFactory, [ 'token' => $token ]));
            $request->attributes->set('errors', (array) $error->getMessageKey());
            return [ SetPasswordInputView::CLASS ];
        }

        return [ SetPasswordSuccessView::CLASS ];
    }

    protected function buildForm(array $data = [])
    {
        return $this->formFactory->createNamedBuilder(null, FormType::CLASS, $data, [ 'translation_domain' => 'form' ])
            ->add('token', HiddenType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('password', RepeatedType::CLASS, [
                'type' => PasswordType::CLASS,
                'constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ],
                'invalid_message' => 'The password fields must match.',
                'required' => true,
                'first_options'  => [ 'label' => 'Password' ],
                'second_options' => [ 'label' => 'Repeat Password' ]
            ])
            ->getForm();
    }
}
