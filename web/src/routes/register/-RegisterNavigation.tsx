import {
  StepNavigation,
  StepNavigationDescription,
  StepNavigationList,
  StepNavigationNumber,
  StepNavigationStep,
  StepNavigationStepHeader,
  StepNavigationTitle,
} from '../../atoms/StepNavigation'

type RegisterNavigationProps = {
  currentStep: 1 | 2 | 3
}

export const RegisterNavigation = ({
  currentStep,
}: RegisterNavigationProps) => {
  return (
    <div>
      <StepNavigation orientation="horizontal" size="normal">
        <p className="sr-only">
          全3ステップ中、{currentStep}ステップ目が進行中
        </p>
        <StepNavigationList>
          <StepNavigationStep
            aria-current={currentStep === 1 ? 'step' : undefined}
            first
            last={false}
            state={currentStep === 1 ? 'reached' : 'completed'}
          >
            <StepNavigationStepHeader>
              <StepNavigationNumber>1</StepNavigationNumber>
              <StepNavigationTitle>新規登録</StepNavigationTitle>
            </StepNavigationStepHeader>
            <StepNavigationDescription>
              必要事項を入力し、アカウントを作成します。
            </StepNavigationDescription>
          </StepNavigationStep>
          <StepNavigationStep
            aria-current={currentStep === 2 ? 'step' : undefined}
            first={false}
            last={false}
            state={
              currentStep === 2
                ? 'reached'
                : currentStep > 2
                  ? 'completed'
                  : undefined
            }
          >
            <StepNavigationStepHeader>
              <StepNavigationNumber>2</StepNavigationNumber>
              <StepNavigationTitle>パスキー登録</StepNavigationTitle>
            </StepNavigationStepHeader>
            <StepNavigationDescription>
              パスキーを登録します
            </StepNavigationDescription>
          </StepNavigationStep>
          <StepNavigationStep
            aria-current={currentStep === 3 ? 'step' : undefined}
            first={false}
            last
            state={currentStep === 3 ? 'reached' : undefined}
          >
            <StepNavigationStepHeader>
              <StepNavigationNumber>3</StepNavigationNumber>
              <StepNavigationTitle>完了</StepNavigationTitle>
            </StepNavigationStepHeader>
            <StepNavigationDescription>
              アカウントの作成が完了しました
            </StepNavigationDescription>
          </StepNavigationStep>
        </StepNavigationList>
      </StepNavigation>
    </div>
  )
}
