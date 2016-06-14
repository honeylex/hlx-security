<?php

namespace Foh\SystemAccount\User\Controller;

use Carbon\Carbon;
use Foh\SystemAccount\User\Model\Aggregate\UserType;
use Foh\SystemAccount\User\Model\Task\CreateUser\UserCreatedEvent;
use Foh\SystemAccount\User\Model\Task\ModifyUser\UserModifiedEvent;
use Foh\SystemAccount\User\Model\Task\ProceedUserWorkflow\UserWorkflowProceededEvent;
use Honeybee\Infrastructure\DataAccess\Storage\StorageReaderMap;
use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Symfony\Component\HttpFoundation\Request;

class HistoryController
{
    protected $userType;

    protected $templateRenderer;

    public function __construct(
        UserType $userType,
        TemplateRendererInterface $templateRenderer,
        StorageReaderMap $storageReaderMap
    ) {
        $this->userType = $userType;
        $this->templateRenderer = $templateRenderer;
        $this->storageReaderMap = $storageReaderMap;
    }

    public function read(Request $request)
    {
        $eventStream = $this->storageReaderMap
            ->getItem($this->userType->getPrefix().'::event_stream::event_source::reader')
                ->read($request->get('identifier'));

        $historyData = [];
        foreach ($eventStream->getEvents()->reverse() as $event) {
            $sentiment = '';
            if ($event instanceof UserCreatedEvent) {
                $type = 'create';
                $sentiment = 'success';
                $title = 'User created';
                $icon = 'glyphicon-plus';
            } elseif ($event instanceof UserModifiedEvent) {
                $type = 'modify';
                $sentiment = 'success';
                $title = 'User data was modified';
                $icon = 'glyphicon-pencil';
            } elseif ($event instanceof UserWorkflowProceededEvent) {
                $title = 'User was ';
                if ($event->getWorkflowState() === 'active') {
                    $sentiment = 'success';
                    $type = 'promote';
                    $title .= 'activated';
                    $icon = 'glyphicon-ok';
                } elseif ($event->getWorkflowState() === 'inactive') {
                    $sentiment = 'warning';
                    $type = 'demote';
                    $title .= 'deactivated';
                    $icon = 'glyphicon-lock';
                } else {
                    $sentiment = 'danger';
                    $title .= 'deleted';
                    $type = 'delete';
                    $icon = 'glyphicon-trash';
                }
            }
            $historyData[] = [
                'type' => $type,
                'badge' => [ 'icon' => $icon, 'sentiment' => $sentiment ],
                'title' => $title,
                'when' => (new Carbon($event->getIsoDate()))->diffForHumans(),
                'changes' => json_encode($event->getData(), JSON_PRETTY_PRINT),
                'revision' => $event->getSeqNumber(),
                'date' => $event->getDateTime()->format('Y-m-d H:i:s')
            ];
        }

        return $this->templateRenderer->render(
            '@SystemAccount/user/history.twig',
            [ 'history' => $historyData ]
        );
    }
}
