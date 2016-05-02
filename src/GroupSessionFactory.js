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
import Messages from "./Messages";
import GroupSession from "./GroupSession";
import SenderKeyChain from "./SenderKeyChain";
import SenderKeyState from "./SenderKeyState";
import UnsupportedProtocolVersionException from "./Exceptions";
import co from "co";

function GroupSessionFactory(crypto, store) {
    const self = this;

    self.processSenderKeyDistributionMessage = (session, senderKeyDistributionMessageBytes) => {
        var senderKeyDistributionMessage =
            Messages.decodeSenderKeyDistributionMessage(senderKeyDistributionMessageBytes);
        if (senderKeyDistributionMessage.version.current !== 3) {
            // TODO: Support protocol version 2
            throw new UnsupportedProtocolVersionException("Protocol version " +
                senderKeyDistributionMessage.version.current + " is not supported");
        }
        var message = senderKeyDistributionMessage.message;

        session = new GroupSession(session);
        session.addState(new SenderKeyState({id: message.getId(),
                                             chain: new SenderKeyChain(message.getChainKey(), message.getIteration()),
                                             signatureKey: message.getSigningKey()}));

        return session;
    };

    Object.freeze(self);
}

export default GroupSessionFactory;
