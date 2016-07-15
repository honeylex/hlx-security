<?php

namespace Hlx\Security\Controller;

use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\LogoutUser\LogoutUserCommand;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Shrink0r\Monatic\Success;
use Silex\Application;
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

    protected $commandBus;

    protected $tokenStorage;

    protected $userType;

    protected $httpUtils;

    public function __construct(
        FormFactoryInterface $formFactory,
        TemplateRendererInterface $templateRenderer,
        CommandBusInterface $commandBus,
        TokenStorageInterface $tokenStorage,
        UserType $userType,
        HttpUtils $httpUtils
    ) {
        $this->formFactory = $formFactory;
        $this->templateRenderer = $templateRenderer;
        $this->commandBus = $commandBus;
        $this->tokenStorage = $tokenStorage;
        $this->userType = $userType;
        $this->httpUtils = $httpUtils;
    }

    public function read(Request $request, Application $app)
    {
        $form = $this->buildLoginForm($this->formFactory);

        return $this->templateRenderer->render(
            '@Security/login.twig',
            [ 'form' => $form->createView() ]
        );
    }

    public function onLogoutSuccess(Request $request)
    {
        $token = $this->tokenStorage->getToken();

        // Reset authentication token for the user on logout
        if ($token instanceof TokenInterface) {
            $user = $token->getUser();
            $result = (new AggregateRootCommandBuilder($this->userType, LogoutUserCommand::CLASS))
                ->withAggregateRootIdentifier($user->getIdentifier())
                ->withKnownRevision($user->getRevision())
                ->withValues([]) // @todo default empty values?
                ->build();

            if (!$result instanceof Success) {
                throw new LogoutException;
            }

            $this->commandBus->post($result->get());
        }

        return $this->httpUtils->createRedirectResponse($request, '/');
    }

    protected function buildLoginForm(FormFactoryInterface $formFactory)
    {
        return $formFactory->createNamedBuilder(null, FormType::CLASS)
            ->add('_username', TextType::CLASS, ['constraints' => [ new NotBlank, new Length([ 'min' => 5 ]) ]])
            ->add('_password', PasswordType::CLASS, [ 'constraints' => new NotBlank ])
            ->getForm();
    }
}
