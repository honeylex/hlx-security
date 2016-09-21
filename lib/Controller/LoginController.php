<?php

namespace Hlx\Security\Controller;

use Hlx\Security\View\LoginInputView;
use Silex\Application;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class LoginController
{
    protected $formFactory;

    public function __construct(FormFactoryInterface $formFactory)
    {
        $this->formFactory = $formFactory;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $request->attributes->set('form', $form);

        return [ LoginInputView::CLASS ];
    }

    protected function buildForm()
    {
        return $this->formFactory->createNamedBuilder(null, FormType::CLASS, [], [ 'translation_domain' => 'form' ])
            ->add('_username', TextType::CLASS, [
                'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ],
                'label' => 'Username or Email'
            ])
            ->add('_password', PasswordType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('_remember_me', CheckboxType::CLASS, [ 'data' => true ])
            ->getForm();
    }
}
