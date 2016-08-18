<?php

namespace Hlx\Security\Controller;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
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

    protected $templateRenderer;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildForm();

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
