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

/**
 * A serialisable representation of a sender key "state".
 */
export default class SenderKeyState {
    /**
     *
     * @param {object} parameters - initial parameters
     */
    constructor(parameters) {
        Object.assign(this, {
            id: 0,
            chain: null,
            signatureKey: null
        }, parameters);
        Object.seal(this);
    }
}
