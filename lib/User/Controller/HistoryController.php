<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\View\HistorySuccessView;
use Honeybee\Infrastructure\DataAccess\Storage\StorageReaderMap;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class HistoryController
{
    protected $userType;

    protected $storageReaderMap;

    public function __construct(UserType $userType, StorageReaderMap $storageReaderMap)
    {
        $this->userType = $userType;
        $this->storageReaderMap = $storageReaderMap;
    }

    public function read(Request $request, Application $app)
    {
        $eventStream = $this->storageReaderMap
            ->getItem($this->userType->getPrefix().'::event_stream::event_source::reader')
            ->read($request->get('identifier'));


        $request->attributes->set('event_stream', $eventStream);

        return [ HistorySuccessView::CLASS ];
    }
}
