/*
   Copyright 2025 ssnob

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once
#include <Windows.h>

namespace sig_scan
{
	unsigned __int64 find_signature(unsigned __int64 start, unsigned __int32 size, unsigned char* bytes, unsigned __int32 byte_size);
	unsigned __int64 find_signature(unsigned __int64 start, unsigned char* bytes, unsigned __int32 byte_size);
};

