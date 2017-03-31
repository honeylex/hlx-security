<?php

namespace Hlx\Security\User\View\Task;

use Honeylex\Renderer\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class ModifyInputView
{
    protected $templateRenderer;

    public function __construct(TemplateRendererInterface $templateRenderer)
    {
        $this->templateRenderer = $templateRenderer;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $form = $request->attributes->get('form');
        $user = $request->attributes->get('user');
        $errors = $request->attributes->get('errors');

        return $this->templateRenderer->render(
            '@hlx-security/user/task/modify.html.twig',
            [ 'form' => $form->createView(), 'user' => $user, 'errors' => $errors ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
