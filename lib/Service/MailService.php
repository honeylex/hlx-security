<?php

namespace Hlx\Security\Service;

use Hlx\Security\User\Projection\Standard\Embed\Verification;
use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\Mail\MailServiceInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Psr\Log\LoggerInterface;
use Honeybee\Infrastructure\Mail\Message;

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

    public function sendVerificationRequestEmail(Verification $token, User $user)
    {
        $message = $this->createMessageFromTemplate(
            '@hlx-security/email/registration_verification.txt.twig',
            [
                'username' => $user->getUsername(),
                'firstname' => $user->getFirstname(),
                'lastname' => $user->getLastname(),
                'verification_token' => $token->getToken(),
                // @todo get global setting from environment
                'project_name' => $this->config->get('project_name')
            ]
        );

        $name = trim($user->getFirstname() . ' ' . $user->getLastname());
        if (empty($name)) {
            $name = $user->getUsername();
        }

        $message->setSubject('Registration verification required');
        $message->setFrom([ $this->config->get('from_email') => $this->config->get('from_name', '') ]);
        $message->setTo([ $user->getEmail() => $name ]);

        if ($senderEmail = $this->config->get('sender_email')) {
            $message->setSender([ $senderEmail => $this->config->get('sender_name', '') ]);
        }

        if ($replyEmail = $this->config->get('reply_email')) {
            $message->setReplyTo([ $replyEmail => $this->config->get('reply_name', '') ]);
        }

        $result = $this->mailService->send($message);

        // @todo something with the result
    }

    protected function createMessageFromTemplate($template, array $templateVars = [])
    {
        $message = new Message;
        $bodyText = $this->templateRenderer->render($template, $templateVars);
        $message->setBodyText($bodyText);
        return $message;
    }
}
