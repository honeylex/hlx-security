<?php

namespace Hlx\Security\View;

use Honeylex\Renderer\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;

class LoginInputView
{
    protected $templateRenderer;

    public function __construct(TemplateRendererInterface $templateRenderer)
    {
        $this->templateRenderer = $templateRenderer;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $form = $request->attributes->get('form');
        $lastUsername = null;
        $error = null;

        if ($request->hasSession()) {
            $session = $request->getSession();
            $lastUsername = $session->get(Security::LAST_USERNAME);
            if ($exception = $session->get(Security::AUTHENTICATION_ERROR)) {
                $error = $exception->getMessage();
                $error = $error ?: $exception->getMessageKey();
                $session->remove(Security::AUTHENTICATION_ERROR);
            }
        }

        return $this->templateRenderer->render(
            '@hlx-security/login.html.twig',
            [
                'form' => $form->createView(),
                'last_username' => $lastUsername,
                'errors' => (array)$error
            ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
