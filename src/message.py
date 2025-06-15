from .scumm6_opcodes import Scumm6Opcodes

from typing import List, NamedTuple, Union

from enum import Enum, auto


class PartType(Enum):
    NEWLINE = auto()
    KEEP_TEXT = auto()
    WAIT = auto()
    INT_MESSAGE = auto()
    VERB_MESSAGE = auto()
    NAME_MESSAGE = auto()
    STRING_MESSAGE = auto()
    START_ANIM = auto()
    SOUND = auto()
    SET_COLOR = auto()
    UNKNOWN13 = auto()
    SET_FONT = auto()


S6Part = Scumm6Opcodes.Message.Part


SS = S6Part.SpecialSequence
MATCH_TYPE = {
    SS.Newline: (PartType.NEWLINE, []),
    SS.KeepText: (PartType.KEEP_TEXT, []),
    SS.Wait: (PartType.WAIT, []),
    SS.IntMessage: (PartType.INT_MESSAGE, ["value"]),
    SS.VerbMessage: (PartType.VERB_MESSAGE, ["value"]),
    SS.NameMessage: (PartType.NAME_MESSAGE, ["value"]),
    SS.StringMessage: (PartType.STRING_MESSAGE, ["value"]),
    SS.StartAnim: (PartType.START_ANIM, ["value"]),
    SS.Sound: (PartType.SOUND, ["value1", "value2"]),
    SS.SetColor: (PartType.SET_COLOR, ["value"]),
    SS.Unknown13: (PartType.UNKNOWN13, ["value"]),
    SS.SetFont: (PartType.SET_FONT, ["value"]),
}


class Part(NamedTuple):
    part_type: PartType
    args: List[int] = []


def parse_message(message: Scumm6Opcodes.Message) -> List[Union[str, Part]]:
    parts: List[Union[str, Part]] = []
    buf = ""

    for p in message.parts:
        if isinstance(p.content, S6Part.Terminator):
            if buf:
                parts.append(buf)
        elif isinstance(p.content, S6Part.SpecialSequence):
            if buf:
                parts.append(buf)
            buf = ""

            payload = p.content.payload
            part_type, args = MATCH_TYPE[type(payload)]

            parts.append(Part(part_type, [getattr(payload, a) for a in args]))
        else:
            assert isinstance(p.content, S6Part.RegularChar)
            buf += chr(p.content.value)

    return parts
