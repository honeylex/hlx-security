<?php

namespace Foh\SystemAccount\User\Controller\Task;

use Foh\SystemAccount\User\Model\Aggregate\UserType;
use Foh\SystemAccount\User\Model\Task\ProceedUserWorkflow\ProceedUserWorkflowCommand;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ProceedWorkflowController
{
    protected $userType;

    protected $commandBus;

    protected $urlGenerator;

    public function __construct(
        UserType $userType,
        CommandBusInterface $commandBus,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
        $this->urlGenerator = $urlGenerator;
    }

    public function write(Request $request, Application $app)
    {
        if ($request->getMethod() !== 'POST') {
            return 'Method not allowed.';
        }
        $proceedCommand = new ProceedUserWorkflowCommand([
            'aggregate_root_type' => $this->userType->getPrefix(),
            'aggregate_root_identifier' => $request->get('identifier'),
            'known_revision' => (int)$request->get('revision'),
            'current_state_name' => $request->get('from'),
            'event_name' => $request->get('via')
        ]);

        $this->commandBus->post($proceedCommand);

        return $app->redirect($this->urlGenerator->generate('foh.system_account.user.list'));
    }
}
