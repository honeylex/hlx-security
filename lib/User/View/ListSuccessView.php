<?php

namespace Hlx\Security\User\View;

use Honeybee\Infrastructure\DataAccess\Finder\FinderResultInterface;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ListSuccessView
{
    protected $templateRenderer;

    protected $urlGenerator;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $search = $request->attributes->get('search');
        $query = $request->attributes->get('search');
        $page = $request->attributes->get('page');
        $limit = $request->attributes->get('limit');

        return $this->templateRenderer->render(
            '@hlx-security/user/list.html.twig',
            [
                'q' => '',
                'user_list' => $search,
                'pager' => $this->buildPager($search, $query, $page, $limit)
            ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }

    protected function buildPager(FinderResultInterface $search, $query, $page, $limit)
    {
        $pager = [
            'total' => ceil($search->getTotalCount() / $limit),
            'current' => $page,
            'next_url' => false,
            'prev_url' => false
        ];

        if (($page + 1) * $limit <= $search->getTotalCount()) {
            $pager['next_url'] = $this->urlGenerator->generate(
                'hlx.security.user.list',
                [ 'page' => $page + 1, 'limit' => $limit, 'q' => $query ]
            );
        }

        if (($page - 1) / $limit > 0) {
            $pager['prev_url'] = $this->urlGenerator->generate(
                'hlx.security.user.list',
                [ 'page' => $page - 1, 'limit' => $limit, 'q' => $query ]
            );
        }

        return $pager;
    }
}
