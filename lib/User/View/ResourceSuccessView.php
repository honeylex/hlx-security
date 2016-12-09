<?php

namespace Hlx\Security\User\View;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;

class ResourceSuccessView
{
    protected $templateRenderer;

    protected $serializer;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        SerializerInterface $serializer
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->serializer = $serializer;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $user = $request->attributes->get('user');

        return $this->templateRenderer->render(
            '@hlx-security/user/resource.html.twig',
            [ 'user' => $user ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        $user = $request->attributes->get('user');

        return new JsonResponse(
            $this->serializer->serialize($user, 'json'),
            JsonResponse::HTTP_OK,
            [],
            true
        );
    }
}
