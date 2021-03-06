<?php

namespace Hlx\Security\User\View;

use Carbon\Carbon;
use Hlx\Security\User\Model\Task\AddToken\TokenAddedEvent;
use Hlx\Security\User\Model\Task\LoginUser\OauthUserLoggedInEvent;
use Hlx\Security\User\Model\Task\LoginUser\UserLoggedInEvent;
use Hlx\Security\User\Model\Task\LogoutUser\UserLoggedOutEvent;
use Hlx\Security\User\Model\Task\ModifyToken\TokenModifiedEvent;
use Hlx\Security\User\Model\Task\ModifyUser\UserModifiedEvent;
use Hlx\Security\User\Model\Task\ProceedUserWorkflow\UserWorkflowProceededEvent;
use Hlx\Security\User\Model\Task\RegisterUser\OauthUserRegisteredEvent;
use Hlx\Security\User\Model\Task\RegisterUser\UserRegisteredEvent;
use Hlx\Security\User\Model\Task\RemoveToken\TokenRemovedEvent;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetEvent;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetStartedEvent;
use Hlx\Security\User\Model\Task\ConnectService\OauthServiceConnectedEvent;
use Honeybee\FrameworkBinding\Silex\Renderer\TemplateRendererInterface;
use Honeybee\Model\Event\AggregateRootEventInterface;
use Honeybee\Model\Event\EventStreamInterface;
use Honeybee\Model\Event\EmbeddedEntityEventList;
use Honeybee\Model\Task\ModifyAggregateRoot\AddEmbeddedEntity\EmbeddedEntityAddedEvent;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyEmbeddedEntity\EmbeddedEntityModifiedEvent;
use Honeybee\Model\Task\ModifyAggregateRoot\RemoveEmbeddedEntity\EmbeddedEntityRemovedEvent;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Serializer\SerializerInterface;

class HistorySuccessView
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
        $eventStream = $request->attributes->get('event_stream');
        $history = $this->buildHistory($eventStream);

        return $this->templateRenderer->render(
            '@hlx-security/user/history.html.twig',
            [ 'history' => $history ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        $eventStream = $request->attributes->get('event_stream');
        $history = $this->buildHistory($eventStream);

        return new JsonResponse(
            $this->serializer->serialize($history, 'json'),
            JsonResponse::HTTP_OK,
            [],
            true
        );
    }

    protected function buildHistory(EventStreamInterface $eventStream)
    {
        $historyData = [];
        foreach ($eventStream->getEvents()->reverse() as $event) {
            $historyData[] = $this->getEventData($event);
        }

        return $historyData;
    }

    protected function getEventData(AggregateRootEventInterface $event)
    {
        $sentiment = '';
        if ($event instanceof OauthUserRegisteredEvent) {
            $type = 'create';
            $sentiment = 'success';
            $title = 'User registered via Oauth';
            $icon = 'glyphicon-plus';
        } elseif ($event instanceof UserRegisteredEvent) {
            $type = 'create';
            $sentiment = 'success';
            $title = 'User registered';
            $icon = 'glyphicon-plus';
        } elseif ($event instanceof UserModifiedEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User data was modified';
            $icon = 'glyphicon-pencil';
        } elseif ($event instanceof OauthServiceConnectedEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User was connected via Oauth';
            $icon = 'glyphicon-flash';
        } elseif ($event instanceof UserWorkflowProceededEvent) {
            $title = 'User was ';
            if ($event->getWorkflowState() === 'verified') {
                $sentiment = 'success';
                $type = 'promote';
                $title .= 'verified';
                $icon = 'glyphicon-ok';
            } elseif ($event->getWorkflowState() === 'unverified') {
                $sentiment = 'warning';
                $title .= 'unverified';
                $type = 'demote';
                $icon = 'glyphicon-lock';
            } elseif ($event->getWorkflowState() === 'deactivated') {
                $sentiment = 'warning';
                $type = 'demote';
                $title .= 'deactivated';
                $icon = 'glyphicon-lock';
            } else {
                $sentiment = 'danger';
                $title .= 'deleted';
                $type = 'delete';
                $icon = 'glyphicon-remove';
            }
        } elseif ($event instanceof UserPasswordSetStartedEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User password set started';
            $icon = 'glyphicon-lock';
        } elseif ($event instanceof UserPasswordSetEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User password set';
            $icon = 'glyphicon-lock';
        } elseif ($event instanceof OauthUserLoggedInEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User logged in via Oauth';
            $icon = 'glyphicon-lock';
        } elseif ($event instanceof UserLoggedInEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User logged in';
            $icon = 'glyphicon-lock';
        } elseif ($event instanceof UserLoggedOutEvent) {
            $type = 'modify';
            $sentiment = 'success';
            $title = 'User logged out';
            $icon = 'glyphicon-lock';
        }

        return [
            'type' => $type,
            'badge' => [ 'icon' => $icon, 'sentiment' => $sentiment ],
            'title' => $title,
            'when' => (new Carbon($event->getIsoDate()))->diffForHumans(),
            'changes' => json_encode($event->getData(), JSON_PRETTY_PRINT),
            'embedded_events' => $this->getEmbeddedEventsData($event->getEmbeddedEntityEvents()),
            'revision' => $event->getSeqNumber(),
            'date' => $event->getDateTime()->format('Y-m-d H:i:s')
        ];
    }

    protected function getEmbeddedEventsData(EmbeddedEntityEventList $eventList)
    {
        $embeddedData = [];
        foreach ($eventList as $embeddedEvent) {
            if ($embeddedEvent instanceof TokenAddedEvent) {
                $title = 'Token added';
            } elseif ($embeddedEvent instanceof TokenModifiedEvent) {
                $title = 'Token modified';
            } elseif ($embeddedEvent instanceof TokenRemovedEvent) {
                $title = 'Token removed';
            } elseif ($embeddedEvent instanceof EmbeddedEntityAddedEvent) {
                $title = 'Embedded entity added';
            } elseif ($embeddedEvent instanceof EmbeddedEntityRemovedEvent) {
                $title = 'Embedded entity removed';
            } elseif ($embeddedEvent instanceof EmbeddedEntityModifiedEvent) {
                $title = 'Embedded entity modfied';
            }
            $embeddedData[] = [
                'title' => $title,
                'changes' => json_encode(
                    [
                        $embeddedEvent->getParentAttributeName() => [
                            array_merge(
                                [
                                    '@type' => $embeddedEvent->getEmbeddedEntityType(),
                                    'identifier' => $embeddedEvent->getEmbeddedEntityIdentifier()
                                ],
                                $embeddedEvent->getData()
                            )
                        ]
                    ],
                    JSON_PRETTY_PRINT
                )
            ];
        }

        return $embeddedData;
    }
}
