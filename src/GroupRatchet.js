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

import HKDF from "./HKDF";
import Chain from "./Chain";
import ArrayBufferUtils from "./ArrayBufferUtils";
import ProtocolConstants from "./ProtocolConstants";
import co from "co";

const messageKeySeed = 0x01;
const chainKeySeed = 0x02;
const whisperGroup = new Uint8Array([87, 104, 105, 115, 112, 101, 114, 71, 114, 111, 117, 112]).buffer;

/**
 * A utility class for performing the Axolotl ratcheting.
 *
 * @param {Crypto} crypto
 * @constructor
 */
function GroupRatchet(crypto) {
    const self = this;

    const hkdf = new HKDF(crypto);

    //
    /**
     * Derive the next sub ratchet state from the previous state.
     * <p>
     * This method "clicks" the hash iteration ratchet forwards.
     *
     * @method
     * @param {Chain} chain
     * @return {Promise.<void, Error>}
     */
    this.clickSubRatchet = co.wrap(function*(chain) {
        chain.index++;
        chain.key = yield deriveNextChainKey(chain.key);
    });

    /**
     * Derive the message keys from the chain key.
     *
     * @method
     * @param {ArrayBuffer} chainKey
     * @return {Promise.<object, Error>} an object containing the message keys.
     */
    this.deriveMessageKeys = co.wrap(function*(chainKey) {
        var messageKey = yield deriveMessageKey(chainKey);
        var keyMaterialBytes = yield hkdf.deriveSecrets(messageKey, whisperGroup,
            ProtocolConstants.cipherKeyByteCount + ProtocolConstants.ivByteCount);
        var ivBytes = keyMaterialBytes.slice(0, ProtocolConstants.ivByteCount);
        var cipherKeyBytes = keyMaterialBytes.slice(ProtocolConstants.ivByteCount);
        return {
            iv: ivBytes,
            cipherKey: cipherKeyBytes
        };
    });

    var hmacByte = co.wrap(function*(key, byte) {
        return yield crypto.hmac(key, ArrayBufferUtils.fromByte(byte));
    });

    var deriveMessageKey = co.wrap(function*(chainKey) {
        return yield hmacByte(chainKey, messageKeySeed);
    });

    var deriveNextChainKey = co.wrap(function*(chainKey) {
        return yield hmacByte(chainKey, chainKeySeed);
    });
}

export default GroupRatchet;
