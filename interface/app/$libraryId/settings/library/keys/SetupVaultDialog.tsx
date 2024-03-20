import { useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
	// insertLibrary,
	// useBridgeMutation,
	// useNormalisedCache,
	usePlausibleEvent,
	useZodForm
} from '@sd/client';
import { Dialog, InputField, PasswordInputField, useDialog, UseDialogProps, z } from '@sd/ui';
import { PasswordMeter } from '~/components';
import { useLocale } from '~/hooks';
import { usePlatform } from '~/util/Platform';

const schema = z.object({
	masterPassword: z
		.string()
		.refine((v) => !v.startsWith(' ') && !v.endsWith(' '), {
			message: "Password can't start or end with a space",
			path: ['masterPassword']
		})
		.refine((v) => v.length < 8, {
			message: 'Password must be at least 8 characters long',
			path: ['masterPassword']
		})
		.refine((v) => !/[A-Z]/.test(v), {
			message: 'Password must contain at least 1 uppercase character',
			path: ['masterPassword']
		})
		.refine((v) => !/\d/.test(v), {
			message: 'Password must contain at least 1 digit',
			path: ['masterPassword']
		}),
	masterPasswordValidate: z.string()
});

export default (props: UseDialogProps) => {
	const { t } = useLocale();

	const navigate = useNavigate();
	const queryClient = useQueryClient();
	const submitPlausibleEvent = usePlausibleEvent();
	const platform = usePlatform();

	// const createLibrary = useBridgeMutation('library.create');

	const form = useZodForm({ schema });
	// const cache = useNormalisedCache();

	const onSubmit = form.handleSubmit(async (data) => {
		if (data.masterPassword !== data.masterPasswordValidate)
			form.setError('masterPasswordValidate', {
				type: 'validate',
				message: t('passwords_do_not_match')
			});
		// try {
		// 	const libraryRaw = await createLibrary.mutateAsync({
		// 		name: data.name,
		// 		default_locations: null
		// 	});
		// 	cache.withNodes(libraryRaw.nodes);
		// 	const library = cache.withCache(libraryRaw.item);
		// 	insertLibrary(queryClient, library);
		// 	submitPlausibleEvent({
		// 		event: { type: 'libraryCreate' }
		// 	});
		// 	platform.refreshMenuBar?.();
		// 	navigate(`/${library.uuid}`);
		// } catch (e) {
		// 	console.error(e);
		// }
	});

	return (
		<Dialog
			form={form}
			onSubmit={onSubmit}
			dialog={useDialog(props)}
			submitDisabled={!form.formState.isValid}
			title={t('setup_vault')}
			description={t('setup_vault_description')}
			ctaLabel={form.formState.isSubmitting ? t('setting_up_vault') : t('setup_vault')}
		>
			<div className="mt-5 space-y-2">
				<PasswordInputField
					{...form.register('masterPassword')}
					label={t('master_password')}
					placeholder={t('master_password_placeholder')}
					size="md"
				/>
				<PasswordInputField
					{...form.register('masterPasswordValidate')}
					label={t('master_password')}
					placeholder={t('master_password_placeholder')}
					size="md"
				/>
				<PasswordMeter password={form.watch('masterPassword')} />
				<InputField
					name="secretKey"
					readOnly
					label={t('secret_key')}
					size="md"
					// ideally needs a clipboard icon
				/>
			</div>
		</Dialog>
	);
};
