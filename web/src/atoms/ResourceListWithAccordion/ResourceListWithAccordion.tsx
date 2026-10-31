import type { ComponentProps } from 'react'
import { Accordion, AccordionContent, AccordionSummary } from '../Accordion'
import type { ResourceListVariant } from '../ResourceList'

export type ResourceListWithAccordionProps = ComponentProps<'details'> & {
  variant: ResourceListVariant
}

export const ResourceListWithAccordion = ({
  children,
  className,
  variant,
  ...rest
}: ResourceListWithAccordionProps) => (
  <Accordion
    className={`
      bg-white text-solid-gray-800 [overflow-wrap:anywhere]
      data-[style=list]:border data-[style=list]:border-transparent data-[style=list]:border-b-solid-gray-420
      data-[style=frame]:rounded-8 data-[style=frame]:border data-[style=frame]:border-solid-gray-420
      ${className ?? ''}
    `}
    data-style={variant}
    {...rest}
  >
    {children}
  </Accordion>
)

export type ResourceListWithAccordionSummaryProps = ComponentProps<'summary'>

export const ResourceListWithAccordionSummary = ({
  children,
  className,
  ...rest
}: ResourceListWithAccordionSummaryProps) => (
  <AccordionSummary
    className={`
      !flex items-center gap-4 rounded-[inherit] !p-4 desktop:!p-4
      group-data-[style=frame]/accordion:!rounded-8
      [&>span:first-child]:!static [&>span:first-child]:!order-last
      [&>span:first-child]:!mt-0 [&>span:first-child]:ml-auto [&>span:first-child]:shrink-0
      ${className ?? ''}
    `}
    {...rest}
  >
    {children}
  </AccordionSummary>
)

export type ResourceListWithAccordionContentProps = ComponentProps<'div'>

export const ResourceListWithAccordionContent = ({
  children,
  className,
  ...rest
}: ResourceListWithAccordionContentProps) => (
  <AccordionContent
    className={`!p-4 desktop:!p-4 ${className ?? ''}`}
    {...rest}
  >
    {children}
  </AccordionContent>
)
