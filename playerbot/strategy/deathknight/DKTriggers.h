#pragma once
#include "playerbot/strategy/triggers/GenericTriggers.h"

namespace ai
{
    
    BUFF_TRIGGER(HornOfWinterTrigger, "horn of winter");
    BUFF_TRIGGER(BoneShieldTrigger, "bone shield");
    BUFF_TRIGGER(ImprovedIcyTalonsTrigger, "improved icy talons");
    DEBUFF_TRIGGER(PlagueStrikeDebuffTrigger, "plague strike");
    DEBUFF_TRIGGER(IcyTouchDebuffTrigger, "icy touch");

		class PlagueStrikeDebuffOnAttackerTrigger : public DebuffOnAttackerTrigger
	{
	public:
		PlagueStrikeDebuffOnAttackerTrigger(PlayerbotAI* ai) : DebuffOnAttackerTrigger(ai, "plague strike") {}
	};
		class IcyTouchDebuffOnAttackerTrigger : public DebuffOnAttackerTrigger
	{
	public:
		IcyTouchDebuffOnAttackerTrigger(PlayerbotAI* ai) : DebuffOnAttackerTrigger(ai, "icy touch") {}
	};

    class DKPresenceTrigger : public BuffTrigger {
    public:
        DKPresenceTrigger(PlayerbotAI* ai) : BuffTrigger(ai, "blood presence") {}
        virtual bool IsActive();
    };

	class BloodTapTrigger : public BuffTrigger {
	public:
		BloodTapTrigger(PlayerbotAI* ai) : BuffTrigger(ai, "blood tap") {}
	};

	class RaiseDeadTrigger : public BuffTrigger {
	public:
		RaiseDeadTrigger(PlayerbotAI* ai) : BuffTrigger(ai, "raise dead") {}
	};


	class RuneStrikeTrigger : public SpellCanBeCastedTrigger {
	public:
		RuneStrikeTrigger(PlayerbotAI* ai) : SpellCanBeCastedTrigger(ai, "rune strike") {}
	};

	class DeathCoilTrigger : public SpellCanBeCastedTrigger {
	public:
		DeathCoilTrigger(PlayerbotAI* ai) : SpellCanBeCastedTrigger(ai, "death coil") {}
	};

	class PestilenceTrigger : public DebuffTrigger {
	public:
		PestilenceTrigger(PlayerbotAI* ai) : DebuffTrigger(ai, "pestilence") {}
	};

	class BloodStrikeTrigger : public DebuffTrigger {
	public:
		BloodStrikeTrigger(PlayerbotAI* ai) : DebuffTrigger(ai, "blood strike") {}
	};


	class HowlingBlastTrigger : public DebuffTrigger {
	public:
		HowlingBlastTrigger(PlayerbotAI* ai) : DebuffTrigger(ai, "howling blast") {}
	};

    class MindFreezeInterruptSpellTrigger : public InterruptSpellTrigger
    {
    public:
		MindFreezeInterruptSpellTrigger(PlayerbotAI* ai) : InterruptSpellTrigger(ai, "mind freeze") {}
    };

	class StrangulateInterruptSpellTrigger : public InterruptSpellTrigger
	{
	public:
		StrangulateInterruptSpellTrigger(PlayerbotAI* ai) : InterruptSpellTrigger(ai, "strangulate") {}
	};

    class KillingMachineTrigger : public BoostTrigger
    {
    public:
		KillingMachineTrigger(PlayerbotAI* ai) : BoostTrigger(ai, "killing machine") {}
    };

    class MindFreezeOnEnemyHealerTrigger : public InterruptEnemyHealerTrigger
    {
    public:
		MindFreezeOnEnemyHealerTrigger(PlayerbotAI* ai) : InterruptEnemyHealerTrigger(ai, "mind freeze") {}
    };

	class ChainsOfIceSnareTrigger : public SnareTargetTrigger
	{
	public:
		ChainsOfIceSnareTrigger(PlayerbotAI* ai) : SnareTargetTrigger(ai, "chains of ice") {}
	};

	class StrangulateOnEnemyHealerTrigger : public InterruptEnemyHealerTrigger
	{
	public:
		StrangulateOnEnemyHealerTrigger(PlayerbotAI* ai) : InterruptEnemyHealerTrigger(ai, "strangulate") {}
	};

    class AutoRuneForgeTrigger : public Trigger {
    public:
        AutoRuneForgeTrigger(PlayerbotAI* ai) : Trigger(ai, "auto runeforge") {}
        virtual bool IsActive() override {
			if (AI_VALUE2(time_t, "manual time", "next runeforge check") > time(0))
				return false;

            return AI_VALUE(bool, "should runeforge");
        }
    };
}
