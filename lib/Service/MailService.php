<?php

namespace Hlx\Security\Service;

use Hlx\Security\User\Projection\Standard\Embed\SetPassword;
use Hlx\Security\User\Projection\Standard\Embed\Verification;
use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\Mail\MailServiceInterface;
use Honeybee\Infrastructure\Mail\Message;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Psr\Log\LoggerInterface;

class MailService
{
    protected $config;

    protected $logger;

    protected $mailService;

    protected $templateRenderer;

    public function __construct(
        ConfigInterface $config,
        LoggerInterface $logger,
        MailServiceInterface $mailService,
        TemplateRendererInterface $templateRenderer
    ) {
        $this->config = $config;
        $this->logger = $logger;
        $this->mailService = $mailService;
        $this->templateRenderer = $templateRenderer;
    }

    public function sendVerificationRequest(Verification $token, User $user)
    {
        $message = $this->createMessageFromTemplate(
            '@hlx-security/email/registration_verification.txt.twig',
            $user,
            [
                'username' => $this->getName($user),
                'verification_token' => $token->getToken(),
                // @todo get global setting from environment
                'project_name' => $this->config->get('project_name')
            ]
        );

        $message->setSubject('Verification required');

        $result = $this->mailService->send($message);
    }

    public function sendSetPasswordInstructions(SetPassword $token, User $user)
    {
        $message = $this->createMessageFromTemplate(
            '@hlx-security/email/set_password.txt.twig',
            $user,
            [
                'username' => $this->getName($user),
                'set_password_token' => $token->getToken()
            ]
        );

        $message->setSubject('Password setting instructions');

        $result = $this->mailService->send($message);
    }

    public function sendPasswordSetNotification(User $user)
    {
        $message = $this->createMessageFromTemplate(
            '@hlx-security/email/password_set.txt.twig',
            $user,
            [ 'username' => $this->getName($user) ]
        );

        $message->setSubject('Your password was set');

        $result = $this->mailService->send($message);
    }

    protected function getName(User $user)
    {
        $name = trim($user->getFirstname() . ' ' . $user->getLastname());
        if (empty($name)) {
            $name = $user->getUsername();
        }
        return $name;
    }

    protected function createMessageFromTemplate($template, User $user, array $templateVars = [])
    {
        $message = new Message;

        $message->setFrom([ $this->config->get('from_email') => $this->config->get('from_name', '') ]);
        $message->setTo([ $user->getEmail() => $this->getName($user) ]);

        if ($senderEmail = $this->config->get('sender_email')) {
            $message->setSender([ $senderEmail => $this->config->get('sender_name', '') ]);
        }

        if ($replyEmail = $this->config->get('reply_email')) {
            $message->setReplyTo([ $replyEmail => $this->config->get('reply_name', '') ]);
        }

        $bodyText = $this->templateRenderer->render($template, $templateVars);
        $message->setBodyText($bodyText);

        return $message;
    }
}
