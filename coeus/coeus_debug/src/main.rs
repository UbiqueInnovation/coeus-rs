// Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use coeus_debug::create_debugger;

fn main() {
    let (mut client, rt) = create_debugger("localhost", 8000).unwrap();
    println!("{}", client.get_version_info_blocking(&rt).unwrap());
}
