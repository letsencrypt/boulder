/*
 * ZLint Copyright 2018 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/* dataupdate.go
 * File used to parse newgtlds.csv and generate a map
 */

package util

import (
	"strings"
)

func HasValidTLD(domain string) bool {
	labels := strings.Split(domain, ".")
	rightLabel := labels[len(labels)-1]
	return IsInTLDMap(rightLabel)
}

func IsInTLDMap(label string) bool {
	label = strings.ToUpper(label)
	if _, ok := tldMap[label]; ok {
		return true
	} else {
		return false
	}
}
