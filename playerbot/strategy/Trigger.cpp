
#include "playerbot/playerbot.h"
#include "Trigger.h"
#include "Action.h"
#include "Entities/Unit.h"
#include "Value.h"

using namespace ai;

Event Trigger::Check()
{
	if (triggered)
	{
		if (owner)
			return Event(getName(), param, owner);
		else
			Event event(getName());
	}

	if (IsActive())
	{
		triggered = !checkAgainInSameTick;
		Event event(getName());
		return event;
	}
	Event event;
	return event;
}

Value<Unit*>* Trigger::GetTargetValue()
{
    return context->GetValue<Unit*>(GetTargetName());
}

Unit* Trigger::GetTarget()
{
    return GetTargetValue()->Get();
}

TriggerNode::~TriggerNode()
{
	NextAction::destroy(handlers);
}

NextAction** TriggerNode::getHandlers()
{
	return NextAction::merge(NextAction::clone(handlers), trigger->getHandlers());
}

float TriggerNode::getFirstRelevance()
{
	return handlers[0] ? handlers[0]->getRelevance() : -1;
}
