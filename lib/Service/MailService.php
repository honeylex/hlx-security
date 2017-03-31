<?php

namespace Hlx\Security\Service;

use Hlx\Security\User\Projection\Standard\Embed\SetPassword;
use Hlx\Security\User\Projection\Standard\Embed\Verification;
use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\FrameworkBinding\Silex\Mail\MailInterface;
use Honeybee\FrameworkBinding\Silex\Mail\MailServiceInterface;
use Honeybee\FrameworkBinding\Silex\Mail\Message;
use Honeybee\FrameworkBinding\Silex\Renderer\TemplateRendererInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Translation\TranslatorInterface;

class MailService
{
    protected $config;

    protected $logger;

    protected $mailService;

    protected $templateRenderer;

    protected $translator;

    public function __construct(
        ConfigInterface $config,
        LoggerInterface $logger,
        MailServiceInterface $mailService,
        TemplateRendererInterface $templateRenderer,
        TranslatorInterface $translator
    ) {
        $this->config = $config;
        $this->logger = $logger;
        $this->mailService = $mailService;
        $this->templateRenderer = $templateRenderer;
        $this->translator = $translator;
    }

    public function sendVerificationRequest(Verification $token, User $user)
    {
        $message = $this->createMessageFromTemplate(
            'registration_verification',
            $user,
            [
                'username' => $this->getName($user),
                'verification_token' => $token->getToken(),
            ]
        );

        $message->setSubject($this->trans('Verification required', $user));

        $result = $this->send($message);
    }

    public function sendSetPasswordInstructions(SetPassword $token, User $user)
    {
        $message = $this->createMessageFromTemplate(
            'set_password',
            $user,
            [
                'username' => $this->getName($user),
                'set_password_token' => $token->getToken()
            ]
        );

        $message->setSubject($this->trans('Password setting instructions', $user));

        $result = $this->send($message);
    }

    public function sendPasswordSetNotification(User $user)
    {
        $message = $this->createMessageFromTemplate(
            'password_set',
            $user,
            [ 'username' => $this->getName($user) ]
        );

        $message->setSubject($this->trans('Your password was set', $user));

        $result = $this->send($message);
    }

    protected function send(MailInterface $message)
    {
        // Handling for persistent transport connections
        $result = $this->mailService->send($message);
        $this->mailService->getMailer()->getTransport()->stop();
        return $result;
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

        // render by user language
        $bodyText = $this->templateRenderer->render(
            sprintf('@hlx-security/email/%s.%s.txt.twig', $template, $user->getLocale()),
            $templateVars
        );

        $message->setBodyText($bodyText);

        return $message;
    }

    protected function trans($key, User $user, array $params = [])
    {
        return $this->translator->trans($key, $params, 'email', $user->getLocale());
    }
}
