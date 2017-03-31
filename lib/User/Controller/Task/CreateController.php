<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\Service\UserManager;
use Hlx\Security\User\View\Task\CreateInputView;
use Hlx\Security\User\View\Task\CreateSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\FormType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Translation\TranslatorInterface;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class CreateController
{
    protected $formFactory;

    protected $translator;

    protected $userProvider;

    protected $userManager;

    public function __construct(
        FormFactoryInterface $formFactory,
        TranslatorInterface $translator,
        UserProviderInterface $userProvider,
        UserManager $userManager
    ) {
        $this->formFactory = $formFactory;
        $this->translator = $translator;
        $this->userProvider = $userProvider;
        $this->userManager = $userManager;
    }

    public function read(Request $request)
    {
        $form = $this->buildForm();
        $request->attributes->set('form', $form);

        return [ CreateInputView::CLASS ];
    }

    public function write(Request $request, Application $app)
    {
        $form = $this->buildForm();
        $form->handleRequest($request);
        $request->attributes->set('form', $form);

        if (!$form->isValid()) {
            return [ CreateInputView::CLASS ];
        }

        $formData = $form->getData();
        $username = $formData['username'];
        $email = $formData['email'];

        try {
            if (!$this->userProvider->userExists($username, $email)) {
                $this->userManager->registerUser($formData);
                return [ CreateSuccessView::CLASS ];
            }
        } catch (AuthenticationException $error) {
            $errors = (array) $error->getMessageKey();
        }

        $request->attributes->set('errors', isset($errors) ? $errors : [ 'User is already registered.' ]);
        return [ CreateInputView::CLASS ];
    }

    protected function buildForm()
    {
        $availableRoles = $this->userManager->getAvailableRoles();
        $availableLocales = $this->translator->getFallbackLocales();

        return $this->formFactory->createBuilder(FormType::CLASS, [], [ 'translation_domain' => 'form' ])
            ->add('username', TextType::CLASS, [ 'constraints' => [ new NotBlank, new Length([ 'min' => 4 ]) ] ])
            ->add('email', EmailType::CLASS, [ 'constraints' => new NotBlank ])
            ->add('locale', ChoiceType::CLASS, [
                'choices' => array_combine($availableLocales, $availableLocales),
                'constraints' => new Choice($availableLocales),
                'translation_domain' => 'locale'
            ])
            ->add('firstname', TextType::CLASS, [ 'required' => false ])
            ->add('lastname', TextType::CLASS, [ 'required' => false ])
            ->add('role', ChoiceType::CLASS, [
                'choices' => array_combine($availableRoles, $availableRoles),
                'constraints' => new Choice($availableRoles),
                'translation_domain' => 'role'
            ])
            ->getForm();
    }
}
