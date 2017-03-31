<?php

namespace Hlx\Security\View;

use Honeylex\Renderer\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Translation\TranslatorInterface;

class RegistrationInputView
{
    protected $templateRenderer;

    protected $translator;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        TranslatorInterface $translator
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->translator = $translator;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $form = $request->attributes->get('form');
        $errors = $request->attributes->get('errors');

        return $this->templateRenderer->render(
            '@hlx-security/registration.html.twig',
            [ 'form' => $form->createView(), 'errors' => $errors ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        // @todo extract form validation errors for JSON response
        $errors = $request->attributes->get('errors');
        $errors = [
            'errors' => [
                'code' => 400,
                'message' => $this->translator->trans($errors[0], [], 'errors')
            ]
        ];

        if ($errors) {
            $jsonResponse = new JsonResponse($errors, JsonResponse::HTTP_BAD_REQUEST);
        } else {
            $jsonResponse = new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
        }

        return $jsonResponse;
    }
}
