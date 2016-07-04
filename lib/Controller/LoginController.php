<?php

namespace Foh\SystemAccount\Controller;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
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
        $form = $this->buildLoginForm($this->formFactory);

        return $this->templateRenderer->render(
            '@SystemAccount/login.twig',
            [ 'form' => $form->createView() ]
        );
    }

    protected function buildLoginForm(FormFactoryInterface $formFactory)
    {
        return $formFactory->createNamedBuilder(null, FormType::CLASS)
            ->add('_username', TextType::CLASS, ['constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ]])
            ->add('_password', PasswordType::CLASS, [ 'constraints' => new NotBlank ])
            ->getForm();
    }
}
