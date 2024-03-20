import { Button, buttonStyles, Card, dialogManager, Tooltip } from '@sd/ui';
import { useLocale } from '~/hooks';

import { Heading } from '../../Layout';
import SetupVaultDialog from './SetupVaultDialog';

export const Component = () => {
	const { t } = useLocale();
	return (
		<>
			<Heading title={t('keys_settings')} description={t('keys_description')} />
			<Button
				variant="gray"
				className="!p-1.5"
				onClick={(e: { stopPropagation: () => void }) => {
					e.stopPropagation();
					dialogManager.create((dp) => (
						<SetupVaultDialog
							{...dp}
							// onSuccess={() => setHide(true)}
							// locationId={location.id}
						/>
					));
				}}
			>
				{t('setup_vault')}
			</Button>
		</>
	);
};
