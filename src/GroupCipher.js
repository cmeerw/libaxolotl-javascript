/**
 * Copyright (C) 2016 Christof Meerwald
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import ArrayBufferUtils from "./ArrayBufferUtils";
import ProtocolConstants from "./ProtocolConstants";
import Messages from "./Messages";
import SenderKeyState from "./SenderKeyState";
import GroupSession from "./GroupSession";
import GroupRatchet from "./GroupRatchet";
import {DuplicateMessageException, InvalidMessageException, UnsupportedProtocolVersionException} from "./Exceptions";
import co from "co";

function GroupCipher(crypto) {
    const self = this;

    const ratchet = new GroupRatchet(crypto);

    self.encryptSenderKeyMessage = co.wrap(function*(state, plaintext) {
        var newState = new SenderKeyState(state);
        var chain = newState.chain;
        var version = {
            current: ProtocolConstants.currentVersion,
            max: ProtocolConstants.currentVersion
        };

        var messageKeys = yield ratchet.deriveMessageKeys(chain.key);
        var ciphertext = yield crypto.encrypt(messageKeys.cipherKey, plaintext, messageKeys.iv);

        var message = {id: newState.id,
                       iteration: chain.index,
                       ciphertext: ciphertext};
        var signatureInput = Messages.encodeSenderKeyMessageSignatureInput({version: version,
                                                                            message: message});

        var signature = yield crypto.sign(newState.signatureKey.private, signatureInput);
        var messageBytes = Messages.encodeSenderKeyMessage({version: version,
                                                            message: message,
                                                            signature: signature});

        yield ratchet.clickSubRatchet(newState.chain);

        return {
            body: messageBytes,
            state: newState
        };
    });

    self.decryptSenderKeyMessage = co.wrap(function*(session, senderKeyMessageBytes) {
        var senderKeyMessage =
            Messages.decodeSenderKeyMessage(senderKeyMessageBytes);
        if (senderKeyMessage.version.current !== 3) {
            // TODO: Support protocol version 2
            throw new UnsupportedProtocolVersionException("Protocol version " +
                senderKeyMessage.version.current + " is not supported");
        }
        var message = senderKeyMessage.message;
        var signatureInput = senderKeyMessage.signatureInput;
        var signature = senderKeyMessage.signature;

        var newSession = new GroupSession(session);
        var exceptions = [];
        for (var state of newSession.states) {
            if (state.id === message.id) {
                var clonedSessionState = new SenderKeyState(state);
                var isValid = yield crypto.verifySignature(state.signatureKey, signatureInput, signature);
                if (!isValid) {
                    exceptions.push(new InvalidMessageException("Bad signature"));
                    continue;
                }
                var promise = decryptSenderKeyMessageWithSessionState(clonedSessionState, message, signature);
                var result = yield promise.catch((e) => {
                    exceptions.push(e);
                });
                if (result !== undefined) {
                    newSession.removeState(state);
                    newSession.addState(clonedSessionState);
                    return {
                        message: result,
                        session: newSession
                    };
                }
            }
        }
        var messages = exceptions.map((e) => e.toString());
        throw new InvalidMessageException("Unable to decrypt message: " + messages);
    });

    var decryptSenderKeyMessageWithSessionState = co.wrap(function*(sessionState, message, signature) {
        var messageKeys = yield getOrCreateMessageKeys(sessionState.chain, message.iteration);

        var plaintext = yield crypto.decrypt(messageKeys.cipherKey, message.ciphertext, messageKeys.iv);

        return plaintext;
    });

    var getOrCreateMessageKeys = co.wrap(function*(chain, counter) {
        if (chain.index > counter) {
            // The message is an old message that has been delivered out of order. We should still have the message
            // key cached unless this is a duplicate message that we've seen before.
            var cachedMessageKeys = chain.messageKeys[counter];
            if (!cachedMessageKeys) {
                throw new DuplicateMessageException("Received message with old counter");
            }
            // We don't want to be able to decrypt this message again, for forward secrecy.
            delete chain.messageKeys[counter];
            return cachedMessageKeys;
        } else {
            // Otherwise, the message is a new message in the chain and we must click the sub ratchet forwards.
            if (counter - chain.index > ProtocolConstants.maximumMissedMessages) {
                throw new InvalidMessageException("Too many skipped messages");
            }
            while (chain.index < counter) {
                // Some messages have not yet been delivered ("skipped") and so we need to catch the sub ratchet up
                // while keeping the message keys for when the messages are eventually delivered.
                chain.messageKeys[chain.index] = yield ratchet.deriveMessageKeys(chain.key);
                yield ratchet.clickSubRatchet(chain);
            }
            var messageKeys = yield ratchet.deriveMessageKeys(chain.key);
            // As we have received the message, we should click the sub ratchet forwards so we can't decrypt it again
            yield ratchet.clickSubRatchet(chain);
            return messageKeys;
        }
    });

    Object.freeze(self);
}

export default GroupCipher;
