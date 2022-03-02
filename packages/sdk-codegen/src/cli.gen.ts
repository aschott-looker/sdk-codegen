/*

 MIT License

 Copyright (c) 2021 Looker Data Sciences, Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.

 */

import type { IVersionInfo } from './codeGen'
import { CodeGen } from './codeGen'
import type {
  ApiModel,
  IMethod,
  IParameter,
  IProperty,
  IType,
} from './sdkModels'

/**
 * CLI generator
 */
export class CliGen extends CodeGen {
  codePath = './cli'
  fileExtension = '.cli'
  nullStr = 'nil'
  packagePath = ''
  commentStr = '// '

  enumDelimiter = '\n'
  indentStr = '  '
  endTypeStr = '}'
  codeQuote = `"`

  useNamedParameters = false
  needsRequestTypes = true

  keywords = new Set<string>([])

  regionToSubCommands = new Map<string, string>()
  currentRegion = ''

  constructor(public api: ApiModel, public versions?: IVersionInfo) {
    super(api, versions)
    this.packageName = `v${this.apiVersion.substring(
      0,
      this.apiVersion.indexOf('.')
    )}`
    this.apiVersion = this.packageName
  }

  beginRegion(_indent: string, description: string): string {
    const [name, desc] = description.split(':').map((str) => str.trim())
    const camelCaseName = name.charAt(0).toLowerCase() + name.slice(1)
    this.currentRegion = `${camelCaseName}Cmd`
    return `
var ${this.currentRegion} = &cobra.Command{
  Use:   "${name}",
  Short: "${desc}",
  Long: "${desc}",
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("${name} called")
  },
}`
  }

  endRegion(_indent: string, _description: string): string {
    return ''
  }

  declareMethod(_indent: string, method: IMethod) {
    const commandName = `${
      method.name.charAt(0).toLowerCase() + method.name.slice(1)
    }Cmd`
    if (this.regionToSubCommands.has(this.currentRegion)) {
      const subCommands = this.regionToSubCommands.get(this.currentRegion)
      this.regionToSubCommands.set(
        this.currentRegion,
        `${subCommands},${commandName}`
      )
    } else {
      this.regionToSubCommands.set(this.currentRegion, commandName)
    }
    return `
var ${commandName} = &cobra.Command{
  Use:   "${method.name}",
  Short: "${method.summary}",
  Long: \`${method.description}\`,
  Run: func(cmd *cobra.Command, args []string) {
    fmt.Println("${method.name} called")
  },
}`
  }

  declareParameter(_indent: string, _method: IMethod, _param: IParameter) {
    return ''
  }

  declareProperty(_indent: string, _property: IProperty) {
    return ''
  }

  encodePathParams(_indent: string, _method: IMethod) {
    return ''
  }

  methodSignature(_indent: string, _method: IMethod) {
    return ''
  }

  methodsEpilogue(indent: string) {
    const addCommands = Array.from(this.regionToSubCommands)
      .map(([key, value]) => {
        const mainCommand = key
        const subCommands = value.split(',')
        const subCommandsString = subCommands
          .map((subCommand) => {
            return `${indent}${mainCommand}.AddCommand(${subCommand})`
          })
          .join('\n')
        return `\n${subCommandsString}\n${indent}rootCmd.AddCommand(${mainCommand})`
      })
      .join('')
    return `
func init() {
${addCommands}
}`
  }

  methodsPrologue(_indent: string) {
    return `
package cmd

import (
  "fmt"

  "github.com/spf13/cobra"
)`
  }

  modelsEpilogue(_indent: string) {
    return ''
  }

  modelsPrologue(_indent: string) {
    return ''
  }

  summary(_indent: string, _text: string) {
    return ''
  }

  commentHeader(
    _indent: string,
    _text: string | undefined,
    _commentStr = ' * '
  ) {
    return ''
  }

  typeSignature(_indent: string, _type: IType) {
    return ''
  }
}
