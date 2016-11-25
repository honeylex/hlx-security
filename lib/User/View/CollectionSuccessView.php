<?php

namespace Hlx\Security\User\View;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;

class CollectionSuccessView
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
        $users = $request->attributes->get('users');

        return $this->templateRenderer->render(
            '@hlx-security/user/collection.html.twig',
            [ 'q' => $request->query->get('q'), 'users' => $users ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        $users = $request->attributes->get('users');

        return new JsonResponse(
            $this->serializer->serialize($users, 'json'),
            JsonResponse::HTTP_OK,
            [],
            true
        );
    }
}
