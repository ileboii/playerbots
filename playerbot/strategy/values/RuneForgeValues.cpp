#include "RuneForgeValues.h"
#include "playerbot/PlayerbotAI.h"
#include "playerbot/ServerFacade.h"
#include "playerbot/strategy/Value.h"
#include "playerbot/strategy/values/ValueContext.h"
#include "Globals/SharedDefines.h"
#include "Server/DBCStructure.h"
#include "Spells/SpellMgr.h"

using namespace ai;

std::vector<uint32> RuneForgeSpellsValue::Calculate() {
    std::vector<uint32> spellIds;

    PlayerSpellMap const& spellMap = bot->GetSpellMap();

    for (auto& spell : spellMap) {
        uint32 spellId = spell.first;

        if (spell.second.state == PLAYERSPELL_REMOVED || spell.second.disabled || IsPassiveSpell(spellId))
            continue;

        SkillLineAbilityMapBounds bounds = sSpellMgr.GetSkillLineAbilityMapBoundsBySpellId(spellId);

        for (auto& bound = bounds.first; bound != bounds.second; ++bound) {
            SkillLineAbilityEntry const* skillLine = bound->second;

            if (!skillLine)
                continue;
#ifdef MANGOSBOT_TWO
            if (skillLine->skillId != SKILL_RUNEFORGING)
#endif
                continue;


            spellIds.push_back(spellId);
        }
    }
    return spellIds;
}

uint32 BestRuneForgeSpellValue::Calculate() {
    std::vector<uint32> available = AI_VALUE(std::vector<uint32>, "runeforge spells");

    if (available.empty()) return 0;

    const uint32 runeFallenCrusader = 53344;
    const uint32 runeRazorice = 53343;
    const uint32 runeCinderglacier = 53331;
    const uint32 runeStoneskinGargoyle = 62158;
    const uint32 runeSwordshattering = 53323;
    const uint32 runeSpellbreaking = 54447;

    PlayerTalentSpec spec = ai->GetTalentSpec();

    bool isPvp = true;
    int32 rpgStyle = AI_VALUE2(int32, "manual saved int", "rpg style override");

    if (rpgStyle < 0)
        rpgStyle = ai->GetFixedBotNumber(BotTypeNumber::RPG_STYLE_NUMBER, 100);

    if (rpgStyle > 20) //20% of the bots use pvp runeforge.
        isPvp = false;

    bool isTank = ai->HasStrategy("tank", ai->GetState()) || spec == PlayerTalentSpec::TALENT_SPEC_DEATH_KNIGHT_BLOOD;

    std::vector<uint32> runeforgePriorityList;
    
    if (isPvp) {
        runeforgePriorityList.push_back(runeSwordshattering);
        runeforgePriorityList.push_back(runeSpellbreaking);
    }
    if (isTank) {
        runeforgePriorityList.push_back(runeStoneskinGargoyle);
        runeforgePriorityList.push_back(runeFallenCrusader);
    }

    switch (spec) {
        case PlayerTalentSpec::TALENT_SPEC_DEATH_KNIGHT_UNHOLY:
            runeforgePriorityList.push_back(runeFallenCrusader);
            break;
        case PlayerTalentSpec::TALENT_SPEC_DEATH_KNIGHT_FROST:
            runeforgePriorityList.push_back(runeRazorice);
            runeforgePriorityList.push_back(runeCinderglacier);
            runeforgePriorityList.push_back(runeFallenCrusader);
            break;
        case PlayerTalentSpec::TALENT_SPEC_DEATH_KNIGHT_BLOOD:
            runeforgePriorityList.push_back(runeStoneskinGargoyle);
            runeforgePriorityList.push_back(runeFallenCrusader);
            break;
        default:
            break;
    }
    // General DPS fallback
    runeforgePriorityList.push_back(runeFallenCrusader);
    runeforgePriorityList.push_back(runeRazorice);
    runeforgePriorityList.push_back(runeCinderglacier);
    runeforgePriorityList.push_back(runeStoneskinGargoyle);
    runeforgePriorityList.push_back(runeSwordshattering);
    runeforgePriorityList.push_back(runeSpellbreaking);
    
    for (auto& wantRune : runeforgePriorityList)
    {
        if (std::find(available.begin(), available.end(), wantRune) == available.end())
            continue;

        return wantRune;
    }

    return available.front();
}

bool ShouldRuneForgeValue::Calculate() {
    uint32 bestSpell = AI_VALUE(uint32, "best runeforge spell");

    if (!bestSpell) 
        return false;

    uint32 bestEnchantId = RuneForgeEnchantFromSpell(bestSpell);

    MANGOS_ASSERT(bestEnchantId); //Runeforge spell does not have enchant id.

    Item* weapon = bot->GetItemByPos(INVENTORY_SLOT_BAG_0, EQUIPMENT_SLOT_MAINHAND);
    if (!weapon) 
        return false;

    uint32 enchantId = weapon->GetEnchantmentId(PERM_ENCHANTMENT_SLOT);


    return enchantId != bestEnchantId;   
} 

uint32 ShouldRuneForgeValue::RuneForgeEnchantFromSpell(uint32 spellId)
{
    const SpellEntry* pSpellInfo = sServerFacade.LookupSpellInfo(spellId);

    if (!pSpellInfo)
        return 0;

    return pSpellInfo->EffectMiscValue[0];
}